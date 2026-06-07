---
id: AND-339
title: Signing API + DTOs
milestone: M7
epic: E44
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  `POST /ui/session/refresh`→retry authenticator, and the `ApiResult<T>` envelope +
  FastAPI `detail` error mapper. AND-339 reuses all of that infrastructure verbatim —
  it only adds a new service interface and DTOs to the same OkHttp client.
  CORRECTED auth model (verified in `src/api/client.ts`): the web client sends THREE
  auth signals on every request — (1) `Authorization: Bearer <accessToken>` from the
  auth store, (2) the `X-CSRF-Token` header echoed from the `ui_csrf` cookie (sent on
  ALL verbs, including GET — not just mutating ones), and (3) cookies via
  `credentials: "include"`. Impersonation adds `X-IMPERSONATION-TOKEN`. The 401 path
  refreshes via `POST /ui/session/refresh` exactly once, then retries. AND-027 must
  supply the Bearer header injection in addition to the cookie/CSRF handling.
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

FR-2. Cover the packet lifecycle endpoints (verified against the backend): create a
packet from an uploaded PDF (`POST /v1/signature-packets`), get a packet detail by
id, mutate fields (`POST .../fields`, action = create/update/delete), fill a single
field (`POST .../fields/{fieldId}/fill`), send the packet, mark it done, acknowledge
the legal notice, and read the audit event log (`GET .../events`).
CORRECTED: there is **no** list-packets, get-documents, bulk-submit, or decline/void
endpoint in the backend; the original draft invented these.

FR-3. Cover the template endpoints (verified): list latest template versions
(`GET /ui/signing/templates`), create the next version of a template
(`POST /ui/signing/templates`), list all versions for a key
(`GET /ui/signing/templates/{templateKey}/versions`), get a specific version, and
run a migration check (`POST /ui/signing/templates/migration-check`).
CORRECTED: templates are versioned by `template_key` + `version` (there is no single
`template_id`), and there is **no** "create packet from template" endpoint.

FR-4. Define Moshi DTOs for: `SignaturePacketDetailDto`, `CreateSignaturePacketResponse`,
`SignatureFieldDto`, `SignaturePacketSignerDto`, `LegalNoticeDto`,
`SignatureTemplateVersionDto`, `SignatureTemplateFieldDto`, the list wrappers
(`SignatureTemplateListDto`, `SignatureTemplateVersionsDto`, `SignaturePacketEventsDto`),
and the request/response bodies in Section 5. CORRECTED: there is **no**
`PagedResponse<T>` for signing — the backend returns plain object wrappers
(`{templates:[...]}`, `{versions:[...]}`, `{events:[...]}`, `{migrations:[...]}`).

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

    // ── Packets (note: /v1 prefix, NOT /ui) ──────────────────────────
    // CORRECTED: there is no list-packets endpoint in the backend. Packets
    // are created from an uploaded PDF source_path, not listed/filtered.

    @POST("v1/signature-packets")
    suspend fun createPacket(
        @Body body: CreateSignaturePacketRequest,
    ): ApiResult<CreateSignaturePacketResponse>

    @GET("v1/signature-packets/{packetId}")
    suspend fun getPacket(
        @Path("packetId") packetId: String,
    ): ApiResult<SignaturePacketDetailDto>

    // CORRECTED: field add/remove is a single mutation endpoint with an
    // action discriminator (create|update|delete), not GET .../documents.
    @POST("v1/signature-packets/{packetId}/fields")
    suspend fun mutateField(
        @Path("packetId") packetId: String,
        @Body body: SignaturePacketFieldMutationRequest,
    ): ApiResult<SignaturePacketFieldMutationResponse>

    // CORRECTED: filling a field is per-field, not a single bulk "submit".
    @POST("v1/signature-packets/{packetId}/fields/{fieldId}/fill")
    suspend fun fillField(
        @Path("packetId") packetId: String,
        @Path("fieldId") fieldId: String,
        @Body body: SignaturePacketFieldFillRequest,
    ): ApiResult<SignaturePacketFieldFillResponse>

    @POST("v1/signature-packets/{packetId}/send")
    suspend fun sendPacket(
        @Path("packetId") packetId: String,
    ): ApiResult<SendSignaturePacketResponse>

    // CORRECTED: completion is "mark-done", there is no "decline" endpoint.
    @POST("v1/signature-packets/{packetId}/mark-done")
    suspend fun markPacketDone(
        @Path("packetId") packetId: String,
    ): ApiResult<SignaturePacketMarkDoneResponse>

    @POST("v1/signature-packets/{packetId}/acknowledge-legal-notice")
    suspend fun acknowledgeLegalNotice(
        @Path("packetId") packetId: String,
    ): ApiResult<SignaturePacketLegalNoticeAckResponse>

    @GET("v1/signature-packets/{packetId}/events")
    suspend fun getPacketEvents(
        @Path("packetId") packetId: String,
    ): ApiResult<SignaturePacketEventsDto>

    // ── Templates (note: /ui/signing/ prefix, versioned by key+version) ─
    // CORRECTED: path is /ui/signing/templates (not /ui/signature-templates);
    // there is no pagination (no cursor/limit); templates are keyed by
    // template_key and identified by (template_key, version) — no template_id.

    @GET("ui/signing/templates")
    suspend fun listTemplates(): ApiResult<SignatureTemplateListDto>

    @POST("ui/signing/templates")
    suspend fun createTemplateVersion(
        @Body body: CreateSignatureTemplateVersionRequest,
    ): ApiResult<SignatureTemplateVersionDto>

    @GET("ui/signing/templates/{templateKey}/versions")
    suspend fun listTemplateVersions(
        @Path("templateKey") templateKey: String,
    ): ApiResult<SignatureTemplateVersionsDto>

    @GET("ui/signing/templates/{templateKey}/versions/{version}")
    suspend fun getTemplateVersion(
        @Path("templateKey") templateKey: String,
        @Path("version") version: Int,
    ): ApiResult<SignatureTemplateVersionDto>

    @POST("ui/signing/templates/migration-check")
    suspend fun checkTemplateMigration(
        @Body body: SignatureTemplateMigrationCheckRequest,
    ): ApiResult<SignatureTemplateMigrationListDto>
}
```

> NOTE (final-pdf): `GET /v1/signature-packets/{packetId}/final-pdf` returns a
> raw PDF byte stream, not JSON. In the web reference it is fetched directly with
> `fetch(...).blob()` (`signaturePackets.ts: downloadSignaturePacketFinalPdf`). On
> Android model it as `suspend fun downloadFinalPdf(...): ApiResult<ResponseBody>`
> using `@Streaming`; it is intentionally omitted from the JSON DTO surface above.

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

CORRECTED against `SignaturePacketDetailOut`, `SignaturePacketField` (web ref),
`SignatureTemplateVersionOut`, and `SignatureTemplateFieldModel`. Key differences
from the original draft: the packet detail carries `owner_user_id`, `source_path`,
`role`, `signers`, `fields`, and a `capabilities` map (not `title`/`documents`/
`document_count`); there is no document grouping — `fields` live directly on the
packet; the field shape uses `field_type` (not `type`), `assigned_signer_id` (not
`recipient_id`), and adds `is_assigned_to_viewer`/`filled_at`/`capture_mode`/
`render_payload`; templates are versioned (`template_key`+`version`) with
`SignatureTemplateFieldModel` fields keyed by `id`/`type`/`label` (no page/geometry).

```kotlin
@JsonClass(generateAdapter = true)
data class SignaturePacketDetailDto(                          // <- SignaturePacketDetailOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: PacketStatus,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "source_path") val sourcePath: String,
    @Json(name = "role") val role: PacketRole,               // "sender" | "signer"
    @Json(name = "signer_status") val signerStatus: String? = null,
    @Json(name = "origin_channel") val originChannel: String? = null,
    @Json(name = "origin_ref") val originRef: String? = null,
    @Json(name = "created_at") val createdAt: String? = null, // ISO-8601 UTC, nullable
    @Json(name = "sent_at") val sentAt: String? = null,
    @Json(name = "completed_at") val completedAt: String? = null,
    @Json(name = "signers") val signers: List<SignaturePacketSignerDto> = emptyList(),
    @Json(name = "fields") val fields: List<SignatureFieldDto> = emptyList(),
    // capabilities is an open string->bool map server-side; model the known keys.
    @Json(name = "capabilities") val capabilities: Map<String, Boolean> = emptyMap(),
    @Json(name = "legal_notice") val legalNotice: LegalNoticeDto? = null,
)

@JsonClass(generateAdapter = true)
data class SignaturePacketSignerDto(
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "status") val status: String,              // "pending" | "completed"
)

@JsonClass(generateAdapter = true)
data class LegalNoticeDto(
    @Json(name = "required") val required: Boolean = false,
    @Json(name = "accepted") val accepted: Boolean = false,
    @Json(name = "version") val version: String = "",
    @Json(name = "text") val text: String = "",
)

@JsonClass(generateAdapter = true)
data class SignatureFieldDto(                                 // <- SignaturePacketField (web ref)
    @Json(name = "field_id") val fieldId: String,
    @Json(name = "field_type") val fieldType: SignatureFieldType, // CORRECTED key
    @Json(name = "page") val page: Int,
    @Json(name = "x") val x: Float,            // coordinate convention unconfirmed (OQ-3)
    @Json(name = "y") val y: Float,
    @Json(name = "width") val width: Float,
    @Json(name = "height") val height: Float,
    @Json(name = "required") val required: Boolean = true,
    @Json(name = "assigned_signer_id") val assignedSignerId: String? = null, // CORRECTED
    @Json(name = "is_assigned_to_viewer") val isAssignedToViewer: Boolean? = null,
    @Json(name = "filled_at") val filledAt: String? = null,
    @Json(name = "value") val value: String? = null,
    @Json(name = "capture_mode") val captureMode: SignatureInputMode? = null,
    // render_payload is an opaque server bag; keep as a nullable map.
    @Json(name = "render_payload") val renderPayload: Map<String, Any?>? = null,
)

// CORRECTED: templates are versioned and carry label-only fields (no geometry).
@JsonClass(generateAdapter = true)
data class SignatureTemplateVersionDto(                       // <- SignatureTemplateVersionOut
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "version") val version: Int,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "fields") val fields: List<SignatureTemplateFieldDto> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,       // epoch seconds (integer), not ISO string
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "is_active") val isActive: Boolean = true,
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateFieldDto(                         // <- SignatureTemplateFieldModel
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: SignatureFieldType,
    @Json(name = "label") val label: String = "",
    @Json(name = "required") val required: Boolean = true,
)

// List/collection wrappers (no PagedResponse — see Section 6).
@JsonClass(generateAdapter = true)
data class SignatureTemplateListDto(
    @Json(name = "templates") val templates: List<SignatureTemplateVersionDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateVersionsDto(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "versions") val versions: List<SignatureTemplateVersionDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignaturePacketEventsDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "events") val events: List<SignaturePacketEventDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignaturePacketEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "actor_user_id") val actorUserId: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "event_payload") val eventPayload: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
)
```

Enums use a Moshi `@JsonClass(generateAdapter = false)` + fallback adapter or the
`EnumJsonAdapter.create(...).withUnknownFallback(...)` helper registered on the
shared Moshi instance:

```kotlin
// CORRECTED status values to match SignaturePacketStatus (web ref / backend):
enum class PacketStatus {
    @Json(name = "draft") DRAFT,
    @Json(name = "sent") SENT,
    @Json(name = "partially_signed") PARTIALLY_SIGNED,
    @Json(name = "completed") COMPLETED,
    @Json(name = "cancelled") CANCELLED,
    @Json(name = "expired") EXPIRED,
    UNKNOWN;
}

// CORRECTED field types: backend enum is signature|initials|date|text|notary_stamp.
// There is NO "checkbox". (OpenAPI schema "SignatureFieldType".)
enum class SignatureFieldType {
    @Json(name = "signature") SIGNATURE,
    @Json(name = "initials") INITIALS,
    @Json(name = "date") DATE,
    @Json(name = "text") TEXT,
    @Json(name = "notary_stamp") NOTARY_STAMP,
    UNKNOWN;
}

enum class PacketRole {
    @Json(name = "sender") SENDER,
    @Json(name = "signer") SIGNER,
    UNKNOWN;
}

enum class SignatureInputMode {
    @Json(name = "typed") TYPED,
    @Json(name = "drawn") DRAWN,
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
.add(PacketRole::class.java,
     EnumJsonAdapter.create(PacketRole::class.java)
        .withUnknownFallback(PacketRole.UNKNOWN))
```

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000/`. All requests
carry session cookies, the `Authorization: Bearer` token, and the `X-CSRF-Token`
header (on every verb), injected by the shared OkHttp interceptors from AND-027.
CORRECTED: the entire table below was rewritten — the original `/ui/signature-packets*`
and `/ui/signature-templates*` paths do not exist in the backend.

| Verb | Path | Body | Returns (200/201 schema) |
|------|------|------|---------|
| POST | `/v1/signature-packets` | `CreateSignaturePacketRequest` | `CreateSignaturePacketResponse` (`CreateSignaturePacketOut`) |
| GET  | `/v1/signature-packets/{packetId}` | — | `SignaturePacketDetailDto` (`SignaturePacketDetailOut`) |
| POST | `/v1/signature-packets/{packetId}/fields` | `SignaturePacketFieldMutationRequest` | `SignaturePacketFieldMutationResponse` (`SignaturePacketFieldMutationOut`) |
| POST | `/v1/signature-packets/{packetId}/fields/{fieldId}/fill` | `SignaturePacketFieldFillRequest` | `SignaturePacketFieldFillResponse` (`SignaturePacketFieldFillOut`) |
| POST | `/v1/signature-packets/{packetId}/send` | `{}` (empty) | `SendSignaturePacketResponse` (`SendSignaturePacketOut`) |
| POST | `/v1/signature-packets/{packetId}/mark-done` | `{}` (empty) | `SignaturePacketMarkDoneResponse` (`SignaturePacketMarkDoneOut`) |
| POST | `/v1/signature-packets/{packetId}/acknowledge-legal-notice` | `{}` (empty) | `SignaturePacketLegalNoticeAckResponse` (`SignaturePacketLegalNoticeAckOut`) |
| GET  | `/v1/signature-packets/{packetId}/events` | — | `SignaturePacketEventsDto` (`SignaturePacketEventsOut`) |
| GET  | `/v1/signature-packets/{packetId}/final-pdf` | — | raw PDF bytes (binary, not JSON) |
| GET  | `/ui/signing/templates` | — | `SignatureTemplateListDto` (`SignatureTemplateListOut`) |
| POST | `/ui/signing/templates` | `CreateSignatureTemplateVersionRequest` | `SignatureTemplateVersionDto` (`SignatureTemplateVersionOut`) |
| GET  | `/ui/signing/templates/{templateKey}/versions` | — | `SignatureTemplateVersionsDto` (`SignatureTemplateVersionsOut`) |
| GET  | `/ui/signing/templates/{templateKey}/versions/{version}` | — | `SignatureTemplateVersionDto` |
| POST | `/ui/signing/templates/migration-check` | `SignatureTemplateMigrationCheckRequest` | `SignatureTemplateMigrationListDto` (`SignatureTemplateMigrationListOut`) |

Request bodies (CORRECTED to match the backend `*In` schemas / web reference):

```kotlin
// POST /v1/signature-packets  (CreateSignaturePacketIn)
@JsonClass(generateAdapter = true)
data class CreateSignaturePacketRequest(
    @Json(name = "source_path") val sourcePath: String,        // path to an uploaded PDF
    @Json(name = "origin_channel") val originChannel: String,  // "share" | "message"
    @Json(name = "origin_ref") val originRef: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreateSignaturePacketResponse(                       // CreateSignaturePacketOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: PacketStatus,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "source_path") val sourcePath: String,
    @Json(name = "origin_channel") val originChannel: String,
    @Json(name = "origin_ref") val originRef: String? = null,
    @Json(name = "created_at") val createdAt: String,
)

// POST /v1/signature-packets/{id}/fields  (SignaturePacketFieldMutationIn)
// action discriminator: create | update | delete. Geometry fields are nullable
// (only "action" is required), so create vs delete reuse one DTO.
@JsonClass(generateAdapter = true)
data class SignaturePacketFieldMutationRequest(
    @Json(name = "action") val action: String,                 // "create" | "update" | "delete"
    @Json(name = "field_id") val fieldId: String? = null,      // required for update/delete
    @Json(name = "field_type") val fieldType: SignatureFieldType? = null,
    @Json(name = "page") val page: Int? = null,
    @Json(name = "x") val x: Float? = null,
    @Json(name = "y") val y: Float? = null,
    @Json(name = "width") val width: Float? = null,
    @Json(name = "height") val height: Float? = null,
    @Json(name = "assigned_signer_id") val assignedSignerId: String? = null,
    @Json(name = "required") val required: Boolean = true,
)

@JsonClass(generateAdapter = true)
data class SignaturePacketFieldMutationResponse(               // SignaturePacketFieldMutationOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "action") val action: String,
    @Json(name = "field_id") val fieldId: String,
    @Json(name = "field") val field: Map<String, Any?>? = null,
)

// POST /v1/signature-packets/{id}/fields/{fieldId}/fill  (SignaturePacketFieldFillIn)
@JsonClass(generateAdapter = true)
data class SignaturePacketFieldFillRequest(
    @Json(name = "value") val value: String? = null,          // text/date string OR base64 image
    @Json(name = "input_mode") val inputMode: SignatureInputMode? = null, // "typed" | "drawn"
    @Json(name = "drawn_strokes") val drawnStrokes: List<List<Float>>? = null,
    // notary_stamp: NotaryStampFieldIn — model only if NOTARY_STAMP is in scope.
)

@JsonClass(generateAdapter = true)
data class SignaturePacketFieldFillResponse(                   // SignaturePacketFieldFillOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "field_id") val fieldId: String,
    @Json(name = "value") val value: String,
    @Json(name = "filled_at") val filledAt: String,
    @Json(name = "filled_by_signer_id") val filledBySignerId: String,
    @Json(name = "capture_mode") val captureMode: String? = null,
)

// POST /ui/signing/templates  (CreateSignatureTemplateVersionIn)
@JsonClass(generateAdapter = true)
data class CreateSignatureTemplateVersionRequest(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "fields") val fields: List<SignatureTemplateFieldDto>,  // minItems 1
)

// POST /ui/signing/templates/migration-check  (SignatureTemplateMigrationCheckIn)
@JsonClass(generateAdapter = true)
data class SignatureTemplateMigrationCheckRequest(
    @Json(name = "pins") val pins: List<SignatureTemplatePinDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignatureTemplatePinDto(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "version") val version: Int,                  // minimum 1
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateMigrationListDto(                  // SignatureTemplateMigrationListOut
    @Json(name = "migrations") val migrations: List<SignatureTemplateMigrationDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SignatureTemplateMigrationDto(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "pinned_version") val pinnedVersion: Int,
    @Json(name = "latest_version") val latestVersion: Int,
    @Json(name = "needs_resigning") val needsResigning: Boolean = true,
)

// Misc response wrappers used above
@JsonClass(generateAdapter = true)
data class SendSignaturePacketResponse(                        // SendSignaturePacketOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: String,
    @Json(name = "sent_at") val sentAt: String,
    @Json(name = "invited_signers") val invitedSigners: Int,
)

@JsonClass(generateAdapter = true)
data class SignaturePacketMarkDoneResponse(                    // SignaturePacketMarkDoneOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "signer_status") val signerStatus: String,
    @Json(name = "packet_status") val packetStatus: String,
    @Json(name = "completed_at") val completedAt: String,
)

@JsonClass(generateAdapter = true)
data class SignaturePacketLegalNoticeAckResponse(             // SignaturePacketLegalNoticeAckOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "accepted") val accepted: Boolean,
    @Json(name = "notice_version") val noticeVersion: String,
)
```

Example `GET /v1/signature-packets/{id}` 200 response (CORRECTED shape — no
`title`/`documents`/`due_at`; fields live on the packet and use `field_type`):

```json
{
  "packet_id": "pk_01HZ...",
  "status": "partially_signed",
  "owner_user_id": "usr_01HX...",
  "source_path": "uploads/agreement.pdf",
  "role": "signer",
  "signer_status": "pending",
  "origin_channel": "share",
  "created_at": "2026-06-01T14:03:22Z",
  "sent_at": "2026-06-01T14:05:00Z",
  "signers": [ { "signer_id": "sgn_1", "status": "pending" } ],
  "fields": [
    { "field_id": "fld_1", "field_type": "signature", "page": 2,
      "x": 0.12, "y": 0.78, "width": 0.30, "height": 0.06,
      "required": true, "value": null, "assigned_signer_id": "sgn_1",
      "is_assigned_to_viewer": true }
  ],
  "capabilities": { "can_edit_fields": false, "can_send": false, "can_fill_fields": true }
}
```

Error responses: the backend returns `422 HTTPValidationError` for body/param
validation failures (`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`) and the
shared `detail`-shaped errors (`string` | `[{msg,...}]` | `{code,...}`) for 4xx/5xx.
These are mapped by the AND-027 error mapper into `ApiResult.Error`. The
`normalizeErrorDetail` logic in `src/api/client.ts` is the contract for the mapper
(string passthrough, array→joined `msg`s, object→`code` mapping). This ticket does
not introduce new error semantics.

## 6. Data & State Management

There is no Room caching, DataStore persistence, or StateFlow in this ticket. The
DTOs are immutable `data class`es; the `SigningApi` returns `suspend` results to be
consumed off the main thread by the (downstream) repository in AND-340/AND-344.

CORRECTED: the signing endpoints do **not** use a `PagedResponse<T>` cursor
envelope. None of the verified signing list endpoints expose `cursor`/`limit`/`total`
or `next_cursor`. Instead they return fixed object wrappers with a single typed list
property — `SignatureTemplateListDto.templates`, `SignatureTemplateVersionsDto.versions`,
`SignaturePacketEventsDto.events`, and `SignatureTemplateMigrationListDto.migrations`
(all defined in Sections 4–5). Do not introduce a generic paging type for this ticket;
if AND-027 already ships a `PagedResponse<T>` it is simply unused by `SigningApi`.
Mapping DTO→domain is owned by AND-344's state machine and is out of scope here.

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
  (`getPacket`, `getPacketEvents`, `listTemplates`, `listTemplateVersions`,
  `getTemplateVersion`) are idempotent and eligible for retry; the POSTs are NOT
  retried. (CORRECTED method names: no `listPackets`/`getPacketDocuments`.)
- **Extra unknown JSON keys** are ignored by Moshi by default — assert via a test
  that includes a `"_debug"` field.

## 8. Security & Privacy

- Signing payloads may carry signature input (the `fill` body's `value` /
  `drawn_strokes`) and PII (signer ids, document content). These ride the same
  Bearer + cookie + CSRF channel as all `/v1/*` and `/ui/*` calls (CORRECTED: signing
  spans both prefixes — packets under `/v1`, templates under `/ui/signing`).
- **Do not log request/response bodies** for signing endpoints in release builds.
  The shared `HttpLoggingInterceptor` must be `Level.NONE` in release (verified in
  AND-027); for signing, additionally add these paths to a redaction allowlist so
  even debug logging masks the fill body's `value`/`drawn_strokes` and the
  `Authorization`/`X-CSRF-Token` headers.
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
that listener's path normalization (collapse `{packetId}`/`{templateKey}`/`{version}`
to avoid high-cardinality metrics, e.g. `/v1/signature-packets/{id}` and
`/ui/signing/templates/{key}/versions/{version}`). Body content is never included in
telemetry per Section 8.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network` using **MockWebServer** + the shared
Moshi instance. These satisfy the acceptance bullet "Signing payloads map (tested)".

1. **Serialization round-trip** (per DTO): build a Kotlin instance → serialize →
   parse → assert structural equality, for `SignaturePacketDetailDto`,
   `SignatureFieldDto`, `SignatureTemplateVersionDto`, and request bodies.
2. **Deserialization from canonical JSON fixtures** stored under
   `core-network/src/test/resources/signing/*.json`, derived from the web reference
   and `/openapi.json` examples.
3. **Endpoint contract tests** (MockWebServer): for each `SigningApi` method,
   enqueue a stub response and assert the recorded request's **method, path,
   query params, and (for POSTs) body JSON** exactly match the contract table in
   Section 5. E.g. `fillField` asserts `POST /v1/signature-packets/pk_1/fields/fld_1/fill`
   with the serialized `value`/`input_mode` body; `createPacket` asserts
   `POST /v1/signature-packets` with `source_path`/`origin_channel`.
4. **Enum fallback tests:** unknown `status`/`field_type` → `UNKNOWN`.
5. **Optional-field tests:** minimal JSON (only required keys) deserializes; extra
   unknown keys are ignored.
6. **Auth header presence:** assert requests carry `Authorization: Bearer` and
   `X-CSRF-Token` when routed through the shared client (smoke-level; full auth
   behavior tested in AND-027). CORRECTED: CSRF is sent on GETs too, not only
   mutating verbs (see `src/api/client.ts`).

Target: 100% of DTO fields exercised by at least one fixture. Repository- and
UI-level signing tests are AND-345's responsibility, not this ticket's.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints): supplies the Retrofit +
  OkHttp + Moshi client, cookie jar, CSRF interceptor, 401-refresh authenticator,
  `ApiResult<T>`, the FastAPI `detail` error mapper, and the Bearer-token interceptor.
  (CORRECTED: signing does not need `PagedResponse<T>`.) AND-339 cannot be implemented
  until that infrastructure is merged.
- **Transitively depends on the `core-network` Moshi/OkHttp wiring** introduced by
  AND-026 (via AND-027).
- **Blocks AND-340** (Packet list + detail) — needs `getPacket`/`SignaturePacketDetailDto`
  DTOs. (Note: there is no backend list-packets endpoint; AND-340's "list" must be
  sourced elsewhere — flag to that ticket's owner.)
- **Blocks AND-344** (Signing ViewModels / state machine) — needs `fillField`/
  `mutateField`, `SignatureFieldDto`, and the field fill/mutation request shapes.
- Indirectly enables AND-342 (capture/placement consumes `SignatureFieldDto`
  geometry) and AND-345 (signing tests).

Recommended order: merge AND-027 → AND-339 → (AND-340 ∥ AND-344) → AND-342 →
AND-345.

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED):** Endpoint paths and field names were reconciled against the
  OpenAPI index/spec and the web reference during this review. Packets live under
  `/v1/signature-packets*`; templates under `/ui/signing/templates*`. See §16 for the
  per-claim audit; remaining unknowns are listed under "Open assumptions".
- **OQ-2 (RESOLVED — re-scoped):** There is **no** "create packet from template"
  endpoint. Packets are created from an uploaded PDF (`source_path`) via
  `POST /v1/signature-packets`; templates are a separate versioned concept consumed
  elsewhere. No multi-step from-template flow exists in the backend.
- **OQ-3 (still open):** Field coordinate convention — `x/y/width/height` are typed as
  `number` in the OpenAPI spec with no documented unit. The web reference does not
  pin the convention either. Documented here as **unverified-assumption (normalized
  0..1)**; load-bearing for AND-342 — confirm with backend before placement math.
- **OQ-4 (RESOLVED):** Signature input is sent **inline** on the per-field fill call
  (`POST .../fields/{fieldId}/fill` with `value` and/or `drawn_strokes`/`input_mode`),
  not via a separate file-upload-then-token flow. No `FileApi` dependency is required
  for the fill path. (Source PDF upload that produces `source_path` is a separate
  Files-epic concern, out of scope here.)
- **Risk:** Unreliable dev host may make MockWebServer the only stable test surface
  — acceptable, since this ticket's acceptance is contract/mapping correctness, not
  live integration.

## 14. Acceptance Criteria

1. `SigningApi` interface exists in `com.testlogon.android.core.network.signing`
   with all fourteen endpoints from Section 5 (nine packet endpoints incl. the
   streaming `final-pdf`, five template endpoints), correct verbs, paths, and
   `suspend` `ApiResult<T>` signatures. (CORRECTED from "eight"; no query params —
   none of the signing endpoints take cursor/limit/status filters.)
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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption)
and an exact SOURCE pointer. OpenAPI pointers use `METHOD /path` and the
`components.schemas.<Name>` schema; frontend pointers use `src/...: symbol`.

1. **Packet base path is `/v1/signature-packets` (not `/ui/signature-packets`).**
   VERDICT: Corrected. SOURCE: OpenAPI `POST /v1/signature-packets`,
   `GET /v1/signature-packets/{packet_id}`; `src/api/endpoints/signaturePackets.ts:
   createSignaturePacket / getSignaturePacketDetail`.
2. **Template base path is `/ui/signing/templates` (not `/ui/signature-templates`).**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/signing/templates`;
   `src/api/endpoints/signatureTemplates.ts: listSignatureTemplates`.
3. **Create-packet body is `{source_path, origin_channel, origin_ref?}` and returns
   `CreateSignaturePacketOut`.** VERDICT: Corrected (draft had no create endpoint).
   SOURCE: OpenAPI `components.schemas.CreateSignaturePacketIn` / `CreateSignaturePacketOut`;
   `signaturePackets.ts: CreateSignaturePacketReq`. Web flow: `SignaturePacketComposer.tsx`
   lines 181-183.
4. **There is NO list-packets, get-documents, bulk-submit, decline/void, or
   create-from-template endpoint.** VERDICT: Corrected (all invented by the draft).
   SOURCE: OpenAPI index — only the nine `/v1/signature-packets*` rows exist (lines
   2413-2421); no `submit`/`decline`/`from-template`/`documents` paths anywhere.
5. **Field mutation is a single `POST .../fields` with `action` create|update|delete.**
   VERDICT: Corrected. SOURCE: OpenAPI `POST /v1/signature-packets/{packet_id}/fields`,
   `components.schemas.SignaturePacketFieldMutationIn`; `signaturePackets.ts:
   createSignaturePacketField / deleteSignaturePacketField`.
6. **Filling is per-field via `POST .../fields/{field_id}/fill` with
   `{value?, input_mode?, drawn_strokes?}`.** VERDICT: Corrected. SOURCE: OpenAPI
   `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`,
   `components.schemas.SignaturePacketFieldFillIn`; `signaturePackets.ts:
   fillSignaturePacketField`.
7. **Lifecycle endpoints: send / mark-done / acknowledge-legal-notice / events /
   final-pdf.** VERDICT: Verified. SOURCE: OpenAPI `POST .../send`, `.../mark-done`,
   `.../acknowledge-legal-notice`, `GET .../events`, `GET .../final-pdf` (index lines
   2415-2421); `signaturePackets.ts: sendSignaturePacket / markSignaturePacketDone /
   acknowledgeSignaturePacketLegalNotice / downloadSignaturePacketFinalPdf`.
8. **`final-pdf` returns raw PDF bytes, not JSON.** VERDICT: Verified. SOURCE:
   OpenAPI `GET .../final-pdf` resp `200:` (no schema/empty); `signaturePackets.ts:
   downloadSignaturePacketFinalPdf` uses `response.blob()`.
9. **`PacketStatus` values: draft|sent|partially_signed|completed|cancelled|expired
   (NOT in_progress/declined/voided).** VERDICT: Corrected. SOURCE:
   `signaturePackets.ts: SignaturePacketStatus`.
10. **`SignatureFieldType` values: signature|initials|date|text|notary_stamp (NOT
    checkbox).** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.SignatureFieldType`;
    `signaturePackets.ts: SignatureFieldType`.
11. **Packet field key is `field_type` (not `type`) and signer link is
    `assigned_signer_id` (not `recipient_id`).** VERDICT: Corrected. SOURCE:
    `signaturePackets.ts: SignaturePacketField`.
12. **Packet detail shape: packet_id/status/owner_user_id/source_path/role/signers/
    fields/capabilities (no title/documents/due_at).** VERDICT: Corrected. SOURCE:
    OpenAPI `components.schemas.SignaturePacketDetailOut`; `signaturePackets.ts:
    SignaturePacketDetail`.
13. **Templates are versioned by `template_key`+`version` (no single `template_id`),
    with label-only fields `{id,type,label,required}` and integer epoch `created_at`.**
    VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.SignatureTemplateVersionOut`,
    `SignatureTemplateFieldModel`; `signatureTemplates.ts: SignatureTemplateVersion /
    SignatureTemplateField`.
14. **List responses use object wrappers (`{templates}`, `{versions}`, `{events}`,
    `{migrations}`), NOT a `PagedResponse<T>` cursor envelope; no cursor/limit query
    params.** VERDICT: Corrected. SOURCE: OpenAPI `SignatureTemplateListOut`,
    `SignatureTemplateVersionsOut`, `SignaturePacketEventsOut`,
    `SignatureTemplateMigrationListOut`; index rows show no `params=` query keys for
    these paths.
15. **Migration-check body wraps pins as `{pins:[{template_key,version}]}`.**
    VERDICT: Verified. SOURCE: OpenAPI `components.schemas.SignatureTemplateMigrationCheckIn`
    / `SignatureTemplatePin`; `signatureTemplates.ts: checkSignatureTemplateMigration`
    (posts `{ pins }`).
16. **Auth: client sends `Authorization: Bearer <accessToken>` AND `X-CSRF-Token`
    (from `ui_csrf` cookie, on every verb) AND cookies (`credentials:"include"`);
    impersonation adds `X-IMPERSONATION-TOKEN`.** VERDICT: Corrected (draft omitted
    the Bearer token and limited CSRF to mutating verbs). SOURCE: `src/api/client.ts`
    lines 157-171.
17. **401 → `POST /ui/session/refresh` once → retry; failure logs out.** VERDICT:
    Verified. SOURCE: `src/api/client.ts: refreshSession` (line 121) and 401 handler
    (lines 194-237).
18. **Error shapes: 422 `HTTPValidationError` for validation; otherwise `detail`
    (string | array of `{msg}` | object with `code`).** VERDICT: Verified. SOURCE:
    OpenAPI index `resp=...422:HTTPValidationError` on every signing row;
    `src/api/client.ts: normalizeErrorDetail` (lines 66-102).
19. **Web compose flow = create packet → add fields → fill fields → send.** VERDICT:
    Verified. SOURCE: `src/pages/files/SignaturePacketComposer.tsx` lines 181-299.
20. **Stack/module choices (Retrofit 2.11, OkHttp 4.12, Moshi 1.15 + KSP codegen,
    `EnumJsonAdapter.withUnknownFallback`, `@Streaming` for binary).** VERDICT:
    Unverified-assumption (framework refs). SOURCE (framework ref):
    Retrofit https://square.github.io/retrofit/ ; Moshi
    https://github.com/square/moshi#enums (EnumJsonAdapter); `@Streaming`
    https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Streaming.html .
    Not derivable from backend/frontend sources — these are Android-side decisions
    inherited from AND-027.

### Corrections made

- Rewrote the entire `SigningApi` interface (§4): wrong base paths
  (`/ui/signature-packets`→`/v1/signature-packets`, `/ui/signature-templates`→
  `/ui/signing/templates`); removed five non-existent endpoints (listPackets,
  getPacketDocuments, submitPacket, declinePacket, createPacketFromTemplate); added
  the real endpoints (createPacket, mutateField, fillField, sendPacket, markPacketDone,
  acknowledgeLegalNotice, getPacketEvents, the five template endpoints, streaming
  final-pdf).
- Rewrote DTOs (§4): packet detail shape, field key `type`→`field_type`,
  `recipient_id`→`assigned_signer_id`, removed `SignatureDocumentDto`/
  `SignaturePacketSummaryDto`, added signer/legal-notice/event/template-version DTOs;
  template fields are label-only (no geometry).
- Corrected enums (§4): `PacketStatus` values and `SignatureFieldType` (`checkbox`→
  `notary_stamp`); added `PacketRole`, `SignatureInputMode`.
- Rewrote the §5 contract table and request/response bodies to match the real `*In`/
  `*Out` schemas (create/fill/mutation/template/migration).
- Removed `PagedResponse<T>` from §6 (signing uses object wrappers).
- Corrected the auth model in §2/§5/§8/§11 (added Bearer token; CSRF on all verbs).
- Updated FR-2/FR-3/FR-4 (§3), retry method names (§7), telemetry path templates
  (§10), test examples (§11), dependency notes (§12), Open Questions (§13), and AC #1
  endpoint count (§14).

### Open assumptions

- **Field coordinate units (OQ-3):** `x/y/width/height` are bare `number` in OpenAPI
  with no documented unit and the web reference does not pin it. Assumed normalized
  (0..1); MUST be confirmed with backend (load-bearing for AND-342).
- **`capabilities` map keys:** OpenAPI types `capabilities` as an open
  `additionalProperties: boolean` map; the web reference observes
  `can_edit_fields`/`can_send`/`can_fill_fields`, but other keys may appear. Modeled
  as `Map<String, Boolean>` to be safe.
- **`render_payload` / `event_payload` shapes:** opaque server objects
  (`additionalProperties: true`); modeled as `Map<String, Any?>`. Exact contents
  unverified.
- **Android stack versions** (Retrofit/OkHttp/Moshi versions, KSP, base URL,
  interceptor wiring) are inherited from AND-027 and not independently verifiable from
  these sources — treated as assumptions pending that ticket.
- **`notary_stamp` fill payload (`NotaryStampFieldIn`):** present in
  `SignaturePacketFieldFillIn` but not modeled in detail here; deferred unless
  NOTARY_STAMP capture is in scope for AND-342/AND-344.

## 17. Test Plan

All cases are JVM/Robolectric unit or MockWebServer contract tests unless noted; this
is a contract-only module, so most run on the **JVM unit/Robolectric** target (no
device). A few auth/transport smoke cases are noted as runnable on the headless
emulator `test35`; none of this ticket's logic requires the physical device (no
camera/biometrics/FCM/WebRTC). Where a downstream UI/instrumented dependency is
implied, it is explicitly marked out-of-scope and traced forward.

- **TC-AND-339-01 — Create packet happy path (contract).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: MockWebServer
  enqueues a 200 `CreateSignaturePacketOut` body. Steps: call
  `createPacket(CreateSignaturePacketRequest("uploads/a.pdf","share"))`; inspect the
  recorded request. Expected: `POST /v1/signature-packets`; JSON body has
  `source_path` and `origin_channel` (and omits `origin_ref` when null); response maps
  to `CreateSignaturePacketResponse` with `packetId`/`status`. Traces: AC-1, AC-2, AC-4.

- **TC-AND-339-02 — Get packet detail deserialization (contract + round-trip).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue the §5
  example `SignaturePacketDetailOut` JSON. Steps: call `getPacket("pk_1")`. Expected:
  `GET /v1/signature-packets/pk_1`; `SignaturePacketDetailDto` populated with
  `field_type`/`assigned_signer_id` mapped correctly, `capabilities` map present,
  `documents`/`title` absent (no such fields). Traces: AC-1, AC-2, AC-5.

- **TC-AND-339-03 — Field mutation create/delete body shape (contract).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue
  `SignaturePacketFieldMutationOut`. Steps: call `mutateField` once with
  action="create" (full geometry) and once with action="delete" (only `field_id`).
  Expected: both POST `/v1/signature-packets/pk_1/fields`; create body includes
  `field_type`/`page`/`x`/`y`/`width`/`height`; delete body includes `action` +
  `field_id` and omits geometry. Traces: AC-1, AC-2, AC-4.

- **TC-AND-339-04 — Fill field happy path (contract).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue
  `SignaturePacketFieldFillOut`. Steps: call
  `fillField("pk_1","fld_1", SignaturePacketFieldFillRequest(value="Jane", inputMode=TYPED))`.
  Expected: `POST /v1/signature-packets/pk_1/fields/fld_1/fill`; body has
  `value`/`input_mode`; response maps `filledAt`/`filledBySignerId`. Traces: AC-1, AC-2, AC-4.

- **TC-AND-339-05 — Template list + versioned key/version paths (contract).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue
  `SignatureTemplateListOut` then `SignatureTemplateVersionOut`. Steps: call
  `listTemplates()` then `getTemplateVersion("nda", 3)`. Expected: `GET
  /ui/signing/templates` (no query params) and `GET /ui/signing/templates/nda/versions/3`;
  `templates`/`fields` lists deserialize; `created_at` parsed as Long epoch. Traces:
  AC-1, AC-2, AC-5.

- **TC-AND-339-06 — Migration-check body wraps pins (contract).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue
  `SignatureTemplateMigrationListOut`. Steps: call `checkTemplateMigration` with two
  pins. Expected: `POST /ui/signing/templates/migration-check`; body is
  `{"pins":[{"template_key":...,"version":...}]}`; response maps `migrations` with
  `needs_resigning` default true. Traces: AC-1, AC-2, AC-4.

- **TC-AND-339-07 — PacketStatus / SignatureFieldType enum mapping + UNKNOWN fallback.**
  Type: unit. Target: JVM unit. Preconditions: shared Moshi with `withUnknownFallback`.
  Steps: deserialize each known status/type value; then deserialize `"status":"archived"`
  and `"field_type":"qrcode"`. Expected: known values map to the right constants;
  unknown values map to `UNKNOWN` (no exception). Traces: AC-3.

- **TC-AND-339-08 — Minimal-required-fields and extra-unknown-keys tolerance.**
  Type: unit. Target: JVM unit. Steps: deserialize a `SignaturePacketDetailDto` JSON
  containing only the required keys (omit all optionals); deserialize another payload
  that adds a `"_debug"` key and a future `"watermark"` field. Expected: both succeed;
  optionals default to null/empty; unknown keys ignored. Traces: AC-5.

- **TC-AND-339-09 — Round-trip serialization for every DTO/request body.**
  Type: unit. Target: JVM unit. Steps: for each DTO and request body (Sections 4-5)
  build an instance → toJson → fromJson → assert structural equality. Expected: no
  field loss; `@Json` names round-trip exactly. Traces: AC-2, AC-5.

- **TC-AND-339-10 — 422 HTTPValidationError mapping.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue a 422 with
  `{"detail":[{"loc":["body","source_path"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: call `createPacket(...)`. Expected: result is `ApiResult.Error` whose message
  equals the joined `msg` per `normalizeErrorDetail` ("field required"); no crash, no
  partial DTO. Traces: AC-4, AC-6.

- **TC-AND-339-11 — Auth headers present (Bearer + CSRF on GET and POST).**
  Type: integration (Robolectric, real OkHttp client from AND-027) → smoke. Target:
  JVM/Robolectric (optionally headless emulator `test35`). Preconditions: auth store
  has an access token; `ui_csrf` cookie set. Steps: route a GET (`getPacket`) and a
  POST (`sendPacket`) through the shared client against MockWebServer. Expected: BOTH
  recorded requests carry `Authorization: Bearer <token>` and `X-CSRF-Token`; cookies
  sent. Traces: AC-6.

- **TC-AND-339-12 — 401 → session refresh → retry once.**
  Type: integration (MockWebServer). Target: JVM/Robolectric. Preconditions:
  authenticated. Steps: enqueue 401 for `getPacket`, a 200 for `POST /ui/session/refresh`,
  then a 200 for the retried `getPacket`. Expected: client refreshes exactly once and
  retries; final result is success; a second consecutive 401 instead triggers logout
  (no infinite loop). Traces: AC-6.

- **TC-AND-339-13 — Flaky-dev-host / offline path.**
  Type: integration (MockWebServer). Target: JVM/Robolectric. Steps: (a) simulate a
  socket timeout / connection drop on a GET (`getPacketEvents`) and assert it surfaces
  as `ApiResult.Error` (network) without crashing; (b) assert idempotent GETs are
  retry-eligible per §7 while POSTs (`fillField`) are NOT auto-retried. Expected:
  graceful error envelope; no duplicate POST on transient failure. Traces: AC-4, AC-6.

- **TC-AND-339-14 — Security: no body logging of fill payloads in release.**
  Type: unit. Target: JVM unit. Preconditions: build the release logging config.
  Steps: assert `HttpLoggingInterceptor.Level == NONE` in release, and that the
  redaction allowlist masks the fill `value`/`drawn_strokes` and `Authorization`/
  `X-CSRF-Token` headers. Expected: signing request/response bodies and auth headers
  never appear in emitted logs. Traces: AC-6, AC-7.

> Out of scope (traced forward, not implemented here): Compose-UI and
> accessibility (content descriptions / focus order on signature fields) and any
> instrumented e2e signing flow are owned by AND-340/AND-342/AND-345. No physical
> device (SM-A156U) case is required for AND-339 — there is no camera, biometrics,
> FCM, or WebRTC surface in a contract-only module.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 (interface, verbs/paths) | TC-01, TC-02, TC-03, TC-04, TC-05 |
| AC-2 (DTOs + `@Json` mappings) | TC-01, TC-02, TC-03, TC-05, TC-09 |
| AC-3 (enum known + UNKNOWN fallback) | TC-07 |
| AC-4 (MockWebServer request matches) | TC-01, TC-03, TC-04, TC-06, TC-10, TC-13 |
| AC-5 (round-trip + minimal/extra keys) | TC-02, TC-05, TC-08, TC-09 |
| AC-6 (Hilt-provided shared client; auth/refresh; no new interceptors) | TC-10, TC-11, TC-12, TC-13, TC-14 |
| AC-7 (scope guard: no UI/repo/VM/persistence) | TC-14 (release-logging only) + out-of-scope note |
