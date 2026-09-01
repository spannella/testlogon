package com.testlogon.android.core.network.signing

import com.squareup.moshi.Json

/**
 * Transport DTOs for the signing INBOX list surface (SUX-008) — the four browse endpoints that did not
 * exist when AND-339 shipped the load-by-id-only API:
 *
 *   GET v1/signature-packets/awaiting          — packets awaiting the caller's signature
 *   GET v1/signature-packets/sent              — packets the caller sent (as owner)
 *   GET v1/signature-packets/completed-for-me  — completed packets the caller signed
 *   GET v1/signature-packets/drafts            — the caller's draft packets
 *
 * All four return the SAME {items, count} envelope ([SigningInboxListDto]). This mirrors the web
 * contract (frontend/src/api/endpoints/signaturePackets.ts SigningInboxItem / SigningInboxList) and the
 * backend Pydantic models (app/routers/signature_packets.py SigningInboxItemOut / SigningInboxListOut).
 *
 * CODEGEN NOTE: like the rest of core-network signing, these decode via the reflective Moshi factory, so
 * every wire key carries an explicit @Json(name=...). All optional fields are nullable with defaults so
 * a sparse row decodes. `status` is a raw String (NOT the [PacketStatus] enum) because the inbox rows
 * echo the packet status verbatim and we render it through [PacketStatus.fromToken] in the domain mapper
 * (keeping the lenient UNKNOWN fallback without a second enum adapter on the wire).
 */

/** One row in a signing inbox list. `packet_id` + `status` are required; everything else is optional. */
data class SigningInboxItemDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: String,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
    @Json(name = "source_name") val sourceName: String? = null,
    @Json(name = "status_chip") val statusChip: String? = null,
    @Json(name = "status_text") val statusText: String? = null,
    @Json(name = "role") val role: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "sent_at") val sentAt: String? = null,
    @Json(name = "completed_at") val completedAt: String? = null,
)

/** The {items, count} envelope returned by all four inbox endpoints. */
data class SigningInboxListDto(
    @Json(name = "items") val items: List<SigningInboxItemDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)
