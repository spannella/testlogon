package com.testlogon.android.core.network.signing

import com.squareup.moshi.Json

/**
 * AND-339 - transport DTOs for the signing endpoint surface (signature packets + templates).
 *
 * CODEGEN NOTE: core-network does NOT apply the Moshi KSP codegen plugin (its build.gradle.kts has the
 * ksp plugin only for Hilt; the dependencies block has no moshi-kotlin-codegen). These DTOs therefore
 * decode/encode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys verbatim,
 * so every wire key is pinned with an explicit @Json(name = ...) (Moshi does NOT auto snake_case).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED (it would require the codegen plugin to
 * have any effect); @Json is the load-bearing part.
 *
 * Optional fields are nullable with null defaults; list fields default to empty; map fields are
 * Map<String, @JvmSuppressWildcards Any?> (the @JvmSuppressWildcards keeps Moshi's generic resolution
 * happy for the loosely-typed payloads). Enum fields decode via the four signing enum adapters.
 *
 * Timestamp typing per contract: the PACKET timestamps (created_at / sent_at / completed_at) and the
 * packet event created_at are ISO-8601 Strings; the TEMPLATE VERSION created_at is an epoch-SECOND
 * Long. These differ deliberately and are kept as the contract specifies.
 */

// ---- Signature packet: detail + nested ----

/** A single signer attached to a packet. */
data class SignaturePacketSignerDto(
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "status") val status: String,
)

/** Legal-notice acknowledgement state for a packet. All fields default so partial bodies decode. */
data class LegalNoticeDto(
    @Json(name = "required") val required: Boolean = false,
    @Json(name = "accepted") val accepted: Boolean = false,
    @Json(name = "version") val version: String = "",
    @Json(name = "text") val text: String = "",
)

/** A placed signature field on a packet. */
data class SignatureFieldDto(
    @Json(name = "field_id") val fieldId: String,
    @Json(name = "field_type") val fieldType: SignatureFieldType,
    @Json(name = "page") val page: Int,
    @Json(name = "x") val x: Float,
    @Json(name = "y") val y: Float,
    @Json(name = "width") val width: Float,
    @Json(name = "height") val height: Float,
    @Json(name = "required") val required: Boolean = true,
    @Json(name = "assigned_signer_id") val assignedSignerId: String? = null,
    @Json(name = "is_assigned_to_viewer") val isAssignedToViewer: Boolean? = null,
    @Json(name = "filled_at") val filledAt: String? = null,
    @Json(name = "value") val value: String? = null,
    @Json(name = "capture_mode") val captureMode: SignatureInputMode? = null,
    @Json(name = "render_payload") val renderPayload: Map<String, @JvmSuppressWildcards Any?>? = null,
)

/** Full detail of a signature packet. packet_id is required (absent -> JsonDataException). */
data class SignaturePacketDetailDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: PacketStatus,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "source_path") val sourcePath: String,
    @Json(name = "role") val role: PacketRole,
    @Json(name = "signer_status") val signerStatus: String? = null,
    @Json(name = "origin_channel") val originChannel: String? = null,
    @Json(name = "origin_ref") val originRef: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "sent_at") val sentAt: String? = null,
    @Json(name = "completed_at") val completedAt: String? = null,
    @Json(name = "signers") val signers: List<SignaturePacketSignerDto> = emptyList(),
    @Json(name = "fields") val fields: List<SignatureFieldDto> = emptyList(),
    @Json(name = "capabilities") val capabilities: Map<String, Boolean> = emptyMap(),
    @Json(name = "legal_notice") val legalNotice: LegalNoticeDto? = null,
)

// ---- Packet events ----

/** A single audit event on a packet (created_at is an ISO-8601 String here). */
data class SignaturePacketEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "actor_user_id") val actorUserId: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "event_payload") val eventPayload: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
)

/** Wrapper for a packet's event list. */
data class SignaturePacketEventsDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "events") val events: List<SignaturePacketEventDto> = emptyList(),
)

// ---- Templates ----

/** A field definition inside a template version. */
data class SignatureTemplateFieldDto(
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: SignatureFieldType,
    @Json(name = "label") val label: String = "",
    @Json(name = "required") val required: Boolean = true,
)

/** A single template version (created_at is an epoch-SECOND Long here, NOT an ISO String). */
data class SignatureTemplateVersionDto(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "version") val version: Int,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "fields") val fields: List<SignatureTemplateFieldDto> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "is_active") val isActive: Boolean = true,
)

/** Wrapper for the template catalog (latest version per key). */
data class SignatureTemplateListDto(
    @Json(name = "templates") val templates: List<SignatureTemplateVersionDto> = emptyList(),
)

/** Wrapper for all versions of one template key. */
data class SignatureTemplateVersionsDto(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "versions") val versions: List<SignatureTemplateVersionDto> = emptyList(),
)

/** Lenient wrapper for a migration-check result (each migration is a loosely-typed map). */
data class SignatureTemplateMigrationListDto(
    @Json(name = "migrations")
    val migrations: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
)

// ---- Request DTOs ----

/** Body for POST v1 signature-packets. origin_channel is "share" or "message". */
data class CreateSignaturePacketRequest(
    @Json(name = "source_path") val sourcePath: String,
    @Json(name = "origin_channel") val originChannel: String,
    @Json(name = "origin_ref") val originRef: String? = null,
)

/** Body for the field create/update/delete mutation. action is "create" / "update" / "delete". */
data class SignaturePacketFieldMutationRequest(
    @Json(name = "action") val action: String,
    @Json(name = "field_id") val fieldId: String? = null,
    @Json(name = "field_type") val fieldType: SignatureFieldType? = null,
    @Json(name = "page") val page: Int? = null,
    @Json(name = "x") val x: Float? = null,
    @Json(name = "y") val y: Float? = null,
    @Json(name = "width") val width: Float? = null,
    @Json(name = "height") val height: Float? = null,
    @Json(name = "required") val required: Boolean? = null,
    @Json(name = "assigned_signer_id") val assignedSignerId: String? = null,
)

/** Body for filling a field. capture_mode is "typed" or "drawn". */
data class SignaturePacketFieldFillRequest(
    @Json(name = "value") val value: String? = null,
    @Json(name = "capture_mode") val captureMode: SignatureInputMode? = null,
    @Json(name = "render_payload") val renderPayload: Map<String, @JvmSuppressWildcards Any?>? = null,
)

/** A field definition supplied when creating a new template version. */
data class CreateSignatureTemplateFieldRequest(
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: SignatureFieldType,
    @Json(name = "label") val label: String,
    @Json(name = "required") val required: Boolean,
)

/** Body for creating a new template version. */
data class CreateSignatureTemplateVersionRequest(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "fields") val fields: List<CreateSignatureTemplateFieldRequest> = emptyList(),
)

/** Body for the template migration-check (lenient: all fields optional). */
data class SignatureTemplateMigrationCheckRequest(
    @Json(name = "template_key") val templateKey: String,
    @Json(name = "from_version") val fromVersion: Int? = null,
    @Json(name = "to_version") val toVersion: Int? = null,
)

// ---- Lenient response DTOs (all fields optional; tolerate sparse server bodies) ----

/** Lenient response for packet creation. */
data class CreateSignaturePacketResponse(
    @Json(name = "packet_id") val packetId: String? = null,
    @Json(name = "status") val status: PacketStatus? = null,
)

/** Lenient response for a field mutation. */
data class SignaturePacketFieldMutationResponse(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "field") val field: SignatureFieldDto? = null,
)

/** Lenient response for a field fill. */
data class SignaturePacketFieldFillResponse(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "field") val field: SignatureFieldDto? = null,
)

/** Lenient response for sending a packet. */
data class SendSignaturePacketResponse(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "status") val status: PacketStatus? = null,
)

/** Lenient response for marking a packet done. */
data class SignaturePacketMarkDoneResponse(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "status") val status: PacketStatus? = null,
)

/** Lenient response for acknowledging the legal notice. */
data class SignaturePacketLegalNoticeAckResponse(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "accepted") val accepted: Boolean? = null,
)

// ---- SUX-005: owner signing-link revoke ----

/** Request body for revoking a signer's public signing link (mirrors RevokeSigningLinkIn). */
data class RevokeSigningLinkRequest(
    @Json(name = "jti") val jti: String,
)

/** Response for revoking a signing link (mirrors RevokeSigningLinkOut). */
data class RevokeSigningLinkResponse(
    @Json(name = "packet_id") val packetId: String? = null,
    @Json(name = "signer_id") val signerId: String? = null,
    @Json(name = "jti") val jti: String? = null,
    @Json(name = "revoked") val revoked: Boolean = false,
)
