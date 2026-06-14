package com.testlogon.android.feature.signing.model

import com.testlogon.android.core.network.signing.LegalNoticeDto
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldDto
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.network.signing.SignaturePacketDetailDto
import com.testlogon.android.core.network.signing.SignaturePacketEventDto
import com.testlogon.android.core.network.signing.SignaturePacketSignerDto
import java.time.Instant

/**
 * AND-340 - feature domain model + DTO mappers for the e-signature packet DETAIL surface.
 *
 * REUSE: the transport comes from AND-339's SigningApi, so the AND-339 signing ENUMS
 * ([PacketStatus] / [PacketRole] / [SignatureFieldType]) are REUSED verbatim (they already carry an
 * UNKNOWN fallback) rather than redefined as parallel Ui enums - the ticket explicitly allows reusing
 * the core-network signing enums in :app, and that is the simplest thing that compiles. All DTO to
 * domain mapping happens BEFORE the typed ApiResult in the repository (mirrors AND-329).
 *
 * NO LIST: there is no backend packet-list endpoint, so there is NO list/summary domain - only the
 * single-packet detail ([SignaturePacket]) + its audit events ([PacketEvent]).
 *
 * TIMESTAMPS: the packet timestamps (created_at / sent_at / completed_at) and the event created_at are
 * ISO-8601 Strings on the wire (AND-339). They are parsed to [Instant] via runCatching so a malformed
 * or absent value degrades to null (never throws).
 */

/** A single signer attached to a packet (the wire carries only an id + status; NO recipient name). */
data class PacketSigner(
    val signerId: String,
    val status: String,
)

/** One placed signature field. A PLACEHOLDER for the AND-341/342 field manifest + capture surface. */
data class PacketField(
    val fieldId: String,
    val fieldType: SignatureFieldType,
    val page: Int,
    val x: Float,
    val y: Float,
    val width: Float,
    val height: Float,
    val required: Boolean,
    val assignedSignerId: String? = null,
    val isAssignedToViewer: Boolean? = null,
    val filledAt: Instant? = null,
    val value: String? = null,
)

/** The legal-notice acknowledgement state for a packet (surfaced read-only here). */
data class PacketLegalNotice(
    val required: Boolean,
    val accepted: Boolean,
    val version: String,
    val text: String,
)

/**
 * Full detail of one signature packet (the DETAIL surface). The viewing user's [role] + the packet
 * [status] drive the status-driven primary action (see PacketDetailViewModel).
 */
data class SignaturePacket(
    val packetId: String,
    val status: PacketStatus,
    val ownerUserId: String,
    val sourcePath: String,
    val role: PacketRole,
    val signerStatus: String? = null,
    val createdAt: Instant? = null,
    val sentAt: Instant? = null,
    val completedAt: Instant? = null,
    val signers: List<PacketSigner> = emptyList(),
    val fields: List<PacketField> = emptyList(),
    val capabilities: Map<String, Boolean> = emptyMap(),
    val legalNotice: PacketLegalNotice? = null,
)

/** A single audit event on a packet (created_at parsed from the ISO string to [Instant]). */
data class PacketEvent(
    val eventId: String,
    val eventType: String,
    val actorUserId: String,
    val createdAt: Instant?,
)

/** Lenient ISO-8601 to [Instant] parse: bad / absent input degrades to null, never throws. */
internal fun parseInstant(iso: String?): Instant? =
    iso?.let { runCatching { Instant.parse(it) }.getOrNull() }

/** Maps the AND-339 signer DTO to the feature domain. */
fun SignaturePacketSignerDto.toDomain(): PacketSigner = PacketSigner(
    signerId = signerId,
    status = status,
)

/** Maps the AND-339 field DTO to the feature domain (enum reused; filled_at ISO to Instant). */
fun SignatureFieldDto.toDomain(): PacketField = PacketField(
    fieldId = fieldId,
    fieldType = fieldType,
    page = page,
    x = x,
    y = y,
    width = width,
    height = height,
    required = required,
    assignedSignerId = assignedSignerId,
    isAssignedToViewer = isAssignedToViewer,
    filledAt = parseInstant(filledAt),
    value = value,
)

/** Maps the AND-339 legal-notice DTO to the feature domain. */
fun LegalNoticeDto.toDomain(): PacketLegalNotice = PacketLegalNotice(
    required = required,
    accepted = accepted,
    version = version,
    text = text,
)

/** Maps the AND-339 packet-detail DTO to the feature domain (enums reused; ISO timestamps to Instant). */
fun SignaturePacketDetailDto.toDomain(): SignaturePacket = SignaturePacket(
    packetId = packetId,
    status = status,
    ownerUserId = ownerUserId,
    sourcePath = sourcePath,
    role = role,
    signerStatus = signerStatus,
    createdAt = parseInstant(createdAt),
    sentAt = parseInstant(sentAt),
    completedAt = parseInstant(completedAt),
    signers = signers.map { it.toDomain() },
    fields = fields.map { it.toDomain() },
    capabilities = capabilities,
    legalNotice = legalNotice?.toDomain(),
)

/** Maps the AND-339 packet-event DTO to the feature domain (created_at ISO to Instant). */
fun SignaturePacketEventDto.toDomain(): PacketEvent = PacketEvent(
    eventId = eventId,
    eventType = eventType,
    actorUserId = actorUserId,
    createdAt = parseInstant(createdAt),
)

/**
 * PURE resolver of the status-driven primary action for the viewing user, from the packet [status] +
 * [role] (+ whether the viewer has any assigned field). The deep submit/sign flow is AND-342/343; this
 * ticket only surfaces the affordance and, for a draft SENDER, wires send().
 *
 *   - DRAFT  + SENDER                       -> [PacketAction.SEND]   (POST .../send),
 *   - SENT / PARTIALLY_SIGNED + SIGNER with an assigned field -> [PacketAction.SIGN] (deferred nav),
 *   - everything else (terminal / no role)  -> [PacketAction.NONE].
 */
fun primaryAction(packet: SignaturePacket): PacketAction = when {
    packet.status == PacketStatus.DRAFT && packet.role == PacketRole.SENDER -> PacketAction.SEND
    packet.role == PacketRole.SIGNER &&
        (packet.status == PacketStatus.SENT || packet.status == PacketStatus.PARTIALLY_SIGNED) &&
        packet.fields.any { it.isAssignedToViewer == true } -> PacketAction.SIGN
    else -> PacketAction.NONE
}

/** The status + role driven primary action affordance for the DETAIL screen. */
enum class PacketAction {
    /** A draft owner can send the packet to its signers (wired here via send()). */
    SEND,

    /** An assigned signer can sign (deep flow deferred to AND-342/343; emits a nav event). */
    SIGN,

    /** Terminal state / no role: no primary action. */
    NONE,
}
