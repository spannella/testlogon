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
 * AND-310 — broadcast input TYPE enum derived from the wire `input_type` string. Unknown / absent values
 * coerce to [UNKNOWN] (never throw). The domain model keeps [BroadcastInput.inputType] as the raw String
 * (AND-308 + IngestViewModel pass "primary" as a String); [BroadcastInput.inputTypeEnum] exposes this
 * derived enum for type-safe UI branching (icon selection) without breaking the existing String usages.
 */
enum class InputType {
    PRIMARY,
    GUEST,
    SCREEN,
    UNKNOWN,
    ;

    companion object {
        /** Coerces a wire `input_type` string to an [InputType]; unknown / null -> [UNKNOWN] (never throws). */
        fun fromWire(value: String?): InputType = when (value?.lowercase()) {
            BroadcastInputType.PRIMARY -> PRIMARY
            BroadcastInputType.GUEST -> GUEST
            BroadcastInputType.SCREEN -> SCREEN
            else -> UNKNOWN
        }
    }
}

/**
 * AND-308 — canonical (DTO-free) ingest input. The host's primary input carries the
 * [ingestUrl] / [streamKey] the engine would publish to. Redaction-safe domain shape.
 *
 * AND-310 EXTENDS this shape with the inputs-management fields ([isLive], [connectedAt], [disconnectedAt],
 * [createdBy], [createdAt], [updatedAt]) plus a client-derived [isProgram] flag. ALL new fields carry
 * DEFAULTS and are appended AFTER the original positional fields, so AND-308's
 * [BroadcastInputCreateOutDto.toDomain] (which omits them) and the existing positional construction in tests
 * still compile unchanged.
 *
 * [inputType] stays a raw String (AND-308 contract); [inputTypeEnum] is the derived [InputType] for UI use.
 * [isProgram] is NOT a wire field — the inputs surface derives it by joining the input against the layout's
 * `primary_input_id` (the input whose id == layout.primaryInputId is the live program source).
 */
data class BroadcastInput(
    val inputId: String,
    val sessionId: String,
    val inputType: String,
    val label: String?,
    val ingestUrl: String?,
    val streamKey: String?,
    val position: Int,
    // ── AND-310 inputs-management fields (defaulted; appended so AND-308 construction still compiles) ──
    val isLive: Boolean = false,
    val isProgram: Boolean = false,
    val connectedAt: Long? = null,
    val disconnectedAt: Long? = null,
    val createdBy: String = "",
    val createdAt: java.time.Instant? = null,
    val updatedAt: java.time.Instant? = null,
) {
    /** AND-310 — derived [InputType] for type-safe UI branching; [inputType] stays the raw wire String. */
    val inputTypeEnum: InputType get() = InputType.fromWire(inputType)
}

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
