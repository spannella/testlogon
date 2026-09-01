package com.testlogon.android.feature.signing.packetlist

import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SigningInboxItemDto
import java.time.Instant

/**
 * SUX-008 — feature domain + DTO mappers for the signing INBOX (the four browse buckets that back the
 * "list packets" surface). This is the piece that turns the AND-344 [PacketStatusFilter] scaffolding
 * (which anticipated a future backend list) into a real list feature now that the awaiting / sent /
 * completed-for-me / drafts endpoints exist.
 *
 * REUSE: the lenient [PacketStatus] enum from core-network is reused verbatim (UNKNOWN fallback). The
 * inbox row `status` is a raw wire String, mapped through [PacketStatus.fromToken] here. Timestamps are
 * ISO-8601 Strings on the wire and parsed to [Instant] via runCatching (malformed/absent -> null, never
 * throws), mirroring [com.testlogon.android.feature.signing.model.SignaturePacket].
 *
 * Android-free + JVM-testable.
 */

/** Which inbox bucket a row belongs to; drives the endpoint called and the section header. */
enum class SigningInboxBucket {
    AWAITING,
    SENT,
    COMPLETED,
    DRAFTS,
}

/** One row in a signing inbox list (mapped from [SigningInboxItemDto]). */
data class SigningInboxItem(
    val packetId: String,
    val status: PacketStatus,
    val ownerUserId: String? = null,
    val sourceName: String? = null,
    val statusChip: String? = null,
    val statusText: String? = null,
    val role: String? = null,
    val createdAt: Instant? = null,
    val sentAt: Instant? = null,
    val completedAt: Instant? = null,
) {
    /** A best-effort display title: the source document name, falling back to the packet id. */
    val displayTitle: String
        get() = sourceName?.takeIf { it.isNotBlank() } ?: packetId
}

/** Parses an optional ISO-8601 instant string; any parse failure or null degrades to null. */
private fun parseInstant(raw: String?): Instant? =
    raw?.takeIf { it.isNotBlank() }?.let { runCatching { Instant.parse(it) }.getOrNull() }

/** Maps a transport inbox row to the feature domain. */
fun SigningInboxItemDto.toDomain(): SigningInboxItem = SigningInboxItem(
    packetId = packetId,
    status = PacketStatus.fromToken(status),
    ownerUserId = ownerUserId,
    sourceName = sourceName,
    statusChip = statusChip,
    statusText = statusText,
    role = role,
    createdAt = parseInstant(createdAt),
    sentAt = parseInstant(sentAt),
    completedAt = parseInstant(completedAt),
)
