package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-308 — wire DTOs + domain + mappers for the broadcast INPUTS control plane (the host-publish ingest
 * inputs).
 *
 * These are plain authenticated control-plane reads/writes with real backend endpoints, so they are fully
 * implemented and testable independent of the FLAGGED native-WebRTC engine. The control plane creates an
 * ingest input (allocating an ingest_url / stream_key / AWS input ARN), then activates / deactivates /
 * removes it; the actual media publish over that input is driven by the FLAGGED
 * [com.testlogon.android.data.webrtc.BroadcastPublisher] and the AND-290
 * [com.testlogon.android.data.webrtc.SignalingRepository.exchangeBroadcastOffer] SDP exchange — NOT here.
 *
 * Base path is `broadcast/sessions/{session_id}/inputs`. Field names are snake_case via [Json]; absent
 * optionals fall back to Kotlin defaults (lenient decode).
 */

/** Allowed ingest input types. "primary" is the host's own camera/mic; guest/screen are secondary feeds. */
object BroadcastInputType {
    const val PRIMARY = "primary"
    const val GUEST = "guest"
    const val SCREEN = "screen"
}

/** BroadcastInputCreateIn — request body for POST `broadcast/sessions/{sessionId}/inputs`. */
@JsonClass(generateAdapter = true)
data class BroadcastInputCreateInDto(
    @Json(name = "input_type") val inputType: String = BroadcastInputType.GUEST,
    @Json(name = "label") val label: String? = null,
)

/** BroadcastInputCreateOut — the allocated ingest input (201). */
@JsonClass(generateAdapter = true)
data class BroadcastInputCreateOutDto(
    @Json(name = "input_id") val inputId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_type") val inputType: String = BroadcastInputType.GUEST,
    @Json(name = "label") val label: String? = null,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "stream_key") val streamKey: String? = null,
    @Json(name = "position") val position: Int = 0,
    @Json(name = "aws_input_arn") val awsInputArn: String? = null,
)

// NOTE: the per-input host-publish SDP exchange (POST .../inputs/{inputId}/webrtc-offer) is already
// modeled + wired by AND-290 as BroadcastWebRtcOfferRequestDto / BroadcastWebRtcAnswerDto in
// data.webrtc.SignalingDtos and driven via SignalingRepository.exchangeBroadcastOffer. AND-308 REUSES that
// path rather than duplicating the call. The two DTOs below carry the verified BroadcastWebRTCOfferIn /
// BroadcastWebRTCOfferOut wire names for documentation/parity within the inputs control plane; the live
// offer/answer exchange uses the AND-290 DTOs, NOT these.

/** BroadcastWebRTCOfferIn — the host's SDP offer for a publish input (verified wire shape; see note). */
@JsonClass(generateAdapter = true)
data class BroadcastWebRTCOfferInDto(
    @Json(name = "sdp_offer") val sdpOffer: String,
)

/** BroadcastWebRTCOfferOut — the SFU's SDP answer (verified wire shape; see note). */
@JsonClass(generateAdapter = true)
data class BroadcastWebRTCOfferOutDto(
    @Json(name = "sdp_answer") val sdpAnswer: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_id") val inputId: String,
)

/**
 * AND-308 — canonical (DTO-free) ingest input. The host's primary input carries the
 * [ingestUrl] / [streamKey] the engine would publish to. Redaction-safe domain shape.
 */
data class BroadcastInput(
    val inputId: String,
    val sessionId: String,
    val inputType: String,
    val label: String?,
    val ingestUrl: String?,
    val streamKey: String?,
    val position: Int,
)

// ─── DTO -> domain mappers (pure; android-free) ──────────────────────────────────────────────────

internal fun BroadcastInputCreateOutDto.toDomain(): BroadcastInput = BroadcastInput(
    inputId = inputId,
    sessionId = sessionId,
    inputType = inputType,
    label = label,
    ingestUrl = ingestUrl,
    streamKey = streamKey,
    position = position,
)
