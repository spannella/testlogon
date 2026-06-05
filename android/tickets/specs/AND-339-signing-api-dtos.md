---
id: AND-339
title: Signing API + DTOs
milestone: M7
epic: E44
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-340, AND-344]
---

# AND-339 — Signing API + DTOs

## 1. Overview & Goal

This ticket delivers the network contract layer for the e-signature feature set: a
Retrofit `SigningApi` service plus the Moshi-serialized DTOs that model **signature
packets** and **signature templates**. It is the direct Kotlin port of the web
reference modules `frontend/src/api/endpoints/signaturePackets.ts` and
`frontend/src/api/endpoints/signatureTemplates.ts` (with shared shapes from
`frontend/src/api/types.ts`).

The goal is narrow and foundational: define every request/response payload, every
endpoint path/verb, and the wire mapping between FastAPI JSON and Kotlin data
classes, with full round-trip serialization tests. **No repository, no ViewModel, no
UI** is in scope — those are owned by downstream tickets. The deliverable is the
"plumbing" that AND-340 (Packet list + detail) and AND-344 (Signing ViewModels)
build upon. Success is measured purely by: the endpoints are callable with correct
paths/verbs/bodies against MockWebServer, and every signing payload deserializes
and re-serializes losslessly (the acceptance bullet: "Signing payloads map
(tested)").

These types live in `core-network` (the `SigningApi` interface and Moshi adapters)
and `core-model` (the domain-facing models, if a mapping boundary is introduced).
For this ticket the DTOs reside in `core-network` under
`com.testlogon.android.core.network.signing` and are the authoritative wire types;
domain models are deferred to AND-344 unless a thin mapper proves trivial here.

## 2. Context & References

- **Web reference (authoritative for shapes):**
  - `frontend/src/api/endpoints/signaturePackets.ts`
  - `frontend/src/api/endpoints/signatureTemplates.ts`
  - `frontend/src/api/types.ts` (shared `SignaturePacket`, `SignatureField`,
    `SignatureTemplate` interfaces)
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — the canonical source for
  exact field names, enums, and required/optional flags. Field names below are
  derived from the web reference and MUST be reconciled against `/openapi.json`
  during implementation (see Open Questions).
- **Dependency AND-027 (AuthApi):** establishes the Retrofit/OkHttp/Moshi stack,
  the persistent cookie jar, the `X-CSRF-Token` echo interceptor, the 401→
  `session/refresh`→retry authenticator, and the `ApiResult<T>` envelope + FastAPI
  `detail` error mapper. AND-339 reuses all of that infrastructure verbatim — it
  only adds a new service interface and DTOs to the same OkHttp client.
- **Downstream consumers:** AND-340 (Packet list + detail UI), AND-344 (Signing
  ViewModels / state machine), AND-342 (Signature capture + placement). AND-345
  covers repo + UI tests for the feature; AND-339 ships only its own DTO/contract
  unit tests.
- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via
  KSP), Coroutines. Module: `core-network`. JDK 17, minSdk 24.

## 3. Functional Requirements

FR-1. Provide a Retrofit interface `SigningApi` exposing every signing endpoint as a
`suspend` function returning `ApiResult<T>` (the typed envelope from AND-027) or a
raw body wrapped by the shared `apiCall {}` helper.

FR-2. Cover the packet lifecycle endpoints: list packets (paginated/filterable),
get a packet by id, get the documents/fields for a packet, and submit/finalize a
signature packet. Map any status-transition endpoints (e.g. decline, void) present
in the reference.

FR-3. Cover the template endpoints: list templates, get a template by id, and
create a packet from a template if the reference exposes it.

FR-4. Define Moshi DTOs for: `SignaturePacketDto`, `SignaturePacketSummaryDto`
(list item), `SignatureDocumentDto`, `SignatureFieldDto`, `SignatureTemplateDto`,
`SignatureTemplateFieldDto`, the request bodies (`SubmitSignaturePacketRequest`,
`CreatePacketFromTemplateRequest`), and the paginated wrapper `PagedResponse<T>` if
not already provided by AND-027.

FR-5. Model all enums (`PacketStatus`, `SignatureFieldType`) as Kotlin enums with a
Moshi `@Json` fallback to an `UNKNOWN` member so unrecognized backend values never
crash deserialization.

FR-6. All field names map exactly to the FastAPI `snake_case` wire format using
`@Json(name = "...")` (Moshi default does not auto-convert). Nullable backend fields
are Kotlin nullable types with sensible defaults.

FR-7. No business logic, caching, or threading decisions beyond `suspend` signatures.
This is a contract-only module.

## 4. Technical Design

### Service interface (`core-network/.../signing/SigningApi.kt`)

```kotlin
package com.testlogon.android.core.network.signing

import com.testlogon.android.core.network.ApiResult
import retrofit2.http.*

interface SigningApi {

    @GET("ui/signature-packets")
    suspend fun listPackets(
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 25,
    ): ApiResult<PagedResponse<SignaturePacketSummaryDto>>

    @GET("ui/signature-packets/{packetId}")
    suspend fun getPacket(
        @Path("packetId") packetId: String,
    ): ApiResult<SignaturePacketDto>

    @GET("ui/signature-packets/{packetId}/documents")
    suspend fun getPacketDocuments(
        @Path("packetId") packetId: String,
    ): ApiResult<List<SignatureDocumentDto>>

    @POST("ui/signature-packets/{packetId}/submit")
    suspend fun submitPacket(
        @Path("packetId") packetId: String,
        @Body body: SubmitSignaturePacketRequest,
    ): ApiResult<SignaturePacketDto>

    @POST("ui/signature-packets/{packetId}/decline")
    suspend fun declinePacket(
        @Path("packetId") packetId: String,
        @Body body: DeclinePacketRequest,
    ): ApiResult<SignaturePacketDto>

    @GET("ui/signature-templates")
    suspend fun listTemplates(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 25,
    ): ApiResult<PagedResponse<SignatureTemplateDto>>

    @GET("ui/signature-templates/{templateId}")
    suspend fun getTemplate(
        @Path("templateId") templateId: String,
    ): ApiResult<SignatureTemplateDto>

    @POST("ui/signature-packets/from-template")
    suspend fun createPacketFromTemplate(
        @Body body: CreatePacketFromTemplateRequest,
    ): ApiResult<SignaturePacketDto>
}
```

`ApiResult<T>` and the `apiCall` adapter come from AND-027 — `SigningApi` adds no new
interceptors. The base URL, cookie jar, CSRF header injection and 401 refresh are
already wired into the shared `OkHttpClient`/`Retrofit` instance; `SigningApi` is
provided via Hilt:

```kotlin
@Provides @Singleton
fun provideSigningApi(retrofit: Retrofit): SigningApi =
    retrofit.create(SigningApi::class.java)
```

### DTOs (`core-network/.../signing/dto/`)

```kotlin
@JsonClass(generateAdapter = true)
data class SignaturePacketSummaryDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "title") val title: String,
    @Json(name = "status") val status: PacketStatus,
    @Json(name = "document_count") val documentCount: Int,
    @Json(name = "field_count") val fieldCount: Int = 0,
    @Json(name = "created_at") val createdAt: String,      // ISO-8601 UTC
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "due_at") val dueAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class SignaturePacketDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "title") val title: String,
    @Json(name = "status") val status: PacketStatus,
    @Json(name = "documents") val documents: List<SignatureDocumentDto> = emptyList(),
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "due_at") val dueAt: String? = null,
    @Json(name = "template_id") val templateId: String? = null,
)

@JsonClass(generateAdapter = true)
data class SignatureDocumentDto(
    @Json(name = "document_id") val documentId: String,
    @Json(name = "name") val name: String,
    @Json(name = "page_count") val pageCount: Int,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "fields") val fields: List<SignatureFieldDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignatureFieldDto(
    @Json(name = "field_id") val fieldId: String,
    @Json(name = "type") val type: SignatureFieldType,
    @Json(name = "page") val page: Int,
    @Json(name = "x") val x: Float,            // 0..1 normalized page coords
    @Json(name = "y") val y: Float,
    @Json(name = "width") val width: Float,
    @Json(name = "height") val height: Float,
    @Json(name = "required") val required: Boolean = true,
    @Json(name = "value") val value: String? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateDto(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "fields") val fields: List<SignatureTemplateFieldDto> = emptyList(),
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateFieldDto(
    @Json(name = "type") val type: SignatureFieldType,
    @Json(name = "page") val page: Int,
    @Json(name = "x") val x: Float,
    @Json(name = "y") val y: Float,
    @Json(name = "width") val width: Float,
    @Json(name = "height") val height: Float,
    @Json(name = "required") val required: Boolean = true,
)
```

Enums use a Moshi `@JsonClass(generateAdapter = false)` + fallback adapter or the
`EnumJsonAdapter.create(...).withUnknownFallback(...)` helper registered on the
shared Moshi instance:

```kotlin
enum class PacketStatus {
    @Json(name = "draft") DRAFT,
    @Json(name = "sent") SENT,
    @Json(name = "in_progress") IN_PROGRESS,
    @Json(name = "completed") COMPLETED,
    @Json(name = "declined") DECLINED,
    @Json(name = "voided") VOIDED,
    UNKNOWN;
}

enum class SignatureFieldType {
    @Json(name = "signature") SIGNATURE,
    @Json(name = "initials") INITIALS,
    @Json(name = "date") DATE,
    @Json(name = "text") TEXT,
    @Json(name = "checkbox") CHECKBOX,
    UNKNOWN;
}
```

Register on the app Moshi builder (or assert the existing builder already adds
`withUnknownFallback`):

```kotlin
.add(PacketStatus::class.java,
     EnumJsonAdapter.create(PacketStatus::class.java)
        .withUnknownFallback(PacketStatus.UNKNOWN))
.add(SignatureFieldType::class.java,
     EnumJsonAdapter.create(SignatureFieldType::class.java)
        .withUnknownFallback(SignatureFieldType.UNKNOWN))
```

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000/`. All requests
carry the session cookies and (for mutating verbs) the `X-CSRF-Token` header,
injected by the shared OkHttp interceptors from AND-027.

| Verb | Path | Body | Returns |
|------|------|------|---------|
| GET  | `/ui/signature-packets?status=&cursor=&limit=` | — | `PagedResponse<SignaturePacketSummaryDto>` |
| GET  | `/ui/signature-packets/{packetId}` | — | `SignaturePacketDto` |
| GET  | `/ui/signature-packets/{packetId}/documents` | — | `List<SignatureDocumentDto>` |
| POST | `/ui/signature-packets/{packetId}/submit` | `SubmitSignaturePacketRequest` | `SignaturePacketDto` |
| POST | `/ui/signature-packets/{packetId}/decline` | `DeclinePacketRequest` | `SignaturePacketDto` |
| POST | `/ui/signature-packets/from-template` | `CreatePacketFromTemplateRequest` | `SignaturePacketDto` |
| GET  | `/ui/signature-templates?cursor=&limit=` | — | `PagedResponse<SignatureTemplateDto>` |
| GET  | `/ui/signature-templates/{templateId}` | — | `SignatureTemplateDto` |

Request bodies:

```kotlin
@JsonClass(generateAdapter = true)
data class SubmitSignaturePacketRequest(
    @Json(name = "field_values") val fieldValues: List<FieldValueDto>,
)

@JsonClass(generateAdapter = true)
data class FieldValueDto(
    @Json(name = "field_id") val fieldId: String,
    // For signature/initials: base64 PNG; for text/date: string; checkbox: "true"/"false"
    @Json(name = "value") val value: String,
)

@JsonClass(generateAdapter = true)
data class DeclinePacketRequest(
    @Json(name = "reason") val reason: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreatePacketFromTemplateRequest(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "title") val title: String? = null,
)
```

Example `GET /ui/signature-packets/{id}` 200 response:

```json
{
  "packet_id": "pk_01HZ...",
  "title": "Onboarding Agreement",
  "status": "in_progress",
  "template_id": "tpl_01HY...",
  "created_at": "2026-06-01T14:03:22Z",
  "updated_at": "2026-06-02T09:11:00Z",
  "due_at": "2026-06-10T00:00:00Z",
  "documents": [
    {
      "document_id": "doc_01HZ...",
      "name": "agreement.pdf",
      "page_count": 3,
      "download_url": "/ui/files/doc_01HZ.../download",
      "fields": [
        { "field_id": "fld_1", "type": "signature", "page": 2,
          "x": 0.12, "y": 0.78, "width": 0.30, "height": 0.06,
          "required": true, "value": null, "recipient_id": "rcp_1" }
      ]
    }
  ]
}
```

Error responses follow the shared FastAPI `detail` shape (`string` |
`[{msg,...}]` | `{code,...}`) and are mapped by the AND-027 error mapper into
`ApiResult.Error`. This ticket does not introduce new error semantics.

## 6. Data & State Management

There is no Room caching, DataStore persistence, or StateFlow in this ticket. The
DTOs are immutable `data class`es; the `SigningApi` returns `suspend` results to be
consumed off the main thread by the (downstream) repository in AND-340/AND-344.

`PagedResponse<T>` is the shared cursor envelope (reused from AND-027 if it exists;
otherwise defined here):

```kotlin
@JsonClass(generateAdapter = true)
data class PagedResponse<T>(
    @Json(name = "items") val items: List<T>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)
```

A generic Moshi adapter for `PagedResponse<T>` is generated per concrete `T` by the
codegen; verify the adapter resolves for `SignaturePacketSummaryDto` and
`SignatureTemplateDto`. Mapping DTO→domain is owned by AND-344's state machine and
is out of scope here.

## 7. Error Handling & Resilience

- **Unknown enum values:** never throw. `PacketStatus`/`SignatureFieldType` fall
  back to `UNKNOWN` via `EnumJsonAdapter.withUnknownFallback`. A unit test asserts a
  payload with `"status": "archived"` deserializes to `UNKNOWN`.
- **Nullable/missing fields:** all optional wire fields are Kotlin nullable with
  defaults so absent keys do not fail deserialization. A test omits every optional
  field and asserts success.
- **Timeouts/retry/refresh:** inherited from AND-027's OkHttp config (~20s call
  timeout against the unreliable dev host; bounded backoff retry on idempotent GETs
  only; single `POST /ui/session/refresh` then retry on 401). The signing GETs
  (`listPackets`, `getPacket`, `getPacketDocuments`, `listTemplates`, `getTemplate`)
  are idempotent and eligible for retry; the POSTs are NOT retried.
- **Extra unknown JSON keys** are ignored by Moshi by default — assert via a test
  that includes a `"_debug"` field.

## 8. Security & Privacy

- Signing payloads may contain rendered signature images (base64 PNG in
  `FieldValueDto.value`) and PII (names, document content). These ride the same
  cookie-authenticated, CSRF-protected channel as all `/ui/*` calls.
- **Do not log request/response bodies** for signing endpoints in release builds.
  The shared `HttpLoggingInterceptor` must be `Level.NONE` in release (verified in
  AND-027); for signing, additionally add these paths to a redaction allowlist so
  even debug logging masks `field_values[].value`.
- The dev backend is **plaintext HTTP** — acceptable only for the dev environment.
  No new cleartext exception is added by this ticket; it reuses the existing
  network-security config.
- DTOs hold no secrets at rest (no persistence in this ticket).

## 9. Accessibility & i18n

N/A for this ticket — there is no UI. Accessibility (content descriptions for
signature fields, focus order) and string localization for status labels are owned
by AND-340 (Packet list + detail) and AND-342 (capture/placement). Note for
downstream: `PacketStatus` enum values are wire constants and MUST be mapped to
localized, human-readable strings in the UI layer, not displayed raw.

## 10. Telemetry & Logging

No analytics events are emitted from a contract-only module. Network-level
telemetry (request timing, error counts) is captured by the shared OkHttp
event listener from AND-027 and tagged by path. Ensure signing paths are included in
that listener's path normalization (collapse `{packetId}`/`{templateId}` to avoid
high-cardinality metrics, e.g. `/ui/signature-packets/{id}`). Body content is never
included in telemetry per Section 8.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network` using **MockWebServer** + the shared
Moshi instance. These satisfy the acceptance bullet "Signing payloads map (tested)".

1. **Serialization round-trip** (per DTO): build a Kotlin instance → serialize →
   parse → assert structural equality, for `SignaturePacketDto`,
   `SignatureFieldDto`, `SignatureTemplateDto`, and request bodies.
2. **Deserialization from canonical JSON fixtures** stored under
   `core-network/src/test/resources/signing/*.json`, derived from the web reference
   and `/openapi.json` examples.
3. **Endpoint contract tests** (MockWebServer): for each `SigningApi` method,
   enqueue a stub response and assert the recorded request's **method, path,
   query params, and (for POSTs) body JSON** exactly match the contract table in
   Section 5. E.g. `submitPacket` asserts `POST /ui/signature-packets/pk_1/submit`
   with the serialized `field_values` array.
4. **Enum fallback tests:** unknown `status`/`type` → `UNKNOWN`.
5. **Optional-field tests:** minimal JSON (only required keys) deserializes; extra
   unknown keys are ignored.
6. **CSRF/cookie header presence:** assert mutating requests carry `X-CSRF-Token`
   when routed through the shared client (smoke-level; full auth behavior tested in
   AND-027).

Target: 100% of DTO fields exercised by at least one fixture. Repository- and
UI-level signing tests are AND-345's responsibility, not this ticket's.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints): supplies the Retrofit +
  OkHttp + Moshi client, cookie jar, CSRF interceptor, 401-refresh authenticator,
  `ApiResult<T>`, the FastAPI `detail` error mapper, and possibly `PagedResponse<T>`.
  AND-339 cannot be implemented until that infrastructure is merged.
- **Transitively depends on the `core-network` Moshi/OkHttp wiring** introduced by
  AND-026 (via AND-027).
- **Blocks AND-340** (Packet list + detail) — needs `listPackets`/`getPacket` DTOs.
- **Blocks AND-344** (Signing ViewModels / state machine) — needs `submitPacket`,
  `SignatureFieldDto`, and field-value request shapes.
- Indirectly enables AND-342 (capture/placement consumes `SignatureFieldDto`
  geometry) and AND-345 (signing tests).

Recommended order: merge AND-027 → AND-339 → (AND-340 ∥ AND-344) → AND-342 →
AND-345.

## 13. Risks & Open Questions

- **OQ-1:** Exact endpoint paths and field names MUST be confirmed against
  `/openapi.json`. The web reference uses `frontend/src/api/endpoints/*.ts` naming;
  the `/ui/` prefix and `snake_case` keys above are the best inference and require
  verification. Any divergence updates only `@Json(name=...)` and `@Path`/`@GET`
  strings.
- **OQ-2:** Is packet creation from a template a single `POST .../from-template`
  call, or a multi-step flow? If multi-step, add the intermediate endpoints.
- **OQ-3:** Field coordinate convention — confirm whether `x/y/width/height` are
  normalized (0..1) or absolute pixels/points. This is load-bearing for AND-342's
  placement math; documented here as normalized pending confirmation.
- **OQ-4:** Are signature image values uploaded inline as base64 in `submit`, or via
  a separate file-upload endpoint returning a token? Inline base64 is assumed; if
  separate, a `FileApi` reference is needed (Files epic E43).
- **Risk:** Unreliable dev host may make MockWebServer the only stable test surface
  — acceptable, since this ticket's acceptance is contract/mapping correctness, not
  live integration.

## 14. Acceptance Criteria

1. `SigningApi` interface exists in `com.testlogon.android.core.network.signing`
   with all eight endpoints from Section 5, correct verbs, paths, query params, and
   `suspend` `ApiResult<T>` signatures.
2. All DTOs and request bodies from Sections 4–5 exist as Moshi `@JsonClass`
   data classes with exact `@Json(name=...)` wire mappings.
3. `PacketStatus` and `SignatureFieldType` enums deserialize known values correctly
   and fall back to `UNKNOWN` on unknown values (tested).
4. MockWebServer contract tests pass: each method's recorded request matches the
   expected method/path/query/body. ("Signing payloads map (tested)".)
5. Round-trip serialization tests pass for every DTO; minimal-required-fields and
   extra-unknown-keys payloads deserialize without error.
6. `SigningApi` is provided via Hilt from the shared `Retrofit` instance; no new
   interceptors or base-URL config are introduced.
7. No UI, repository, ViewModel, or persistence code is added (scope guard).

## 15. Definition of Done

- Code merged to `android-port` under `android/core-network/...signing/`, building
  with Gradle 8.9 / AGP 8.7.3 / JDK 17 (KSP Moshi codegen succeeds).
- All unit tests green in CI; `core-network` test task passes locally and on CI.
- Field names/paths reconciled against `/openapi.json` (OQ-1) or remaining
  discrepancies recorded as follow-up notes on AND-340/AND-344.
- ktlint/detekt clean; no body logging of signing endpoints in release (Section 8).
- Public types (`SigningApi`, DTOs, enums) have KDoc noting the web-reference
  source file.
- AND-340 and AND-344 can compile against the published interface (verified by a
  smoke compile or stub consumer).
- PR description links the two reference TS modules and `/openapi.json`; reviewer
  from the networking owners signs off.
