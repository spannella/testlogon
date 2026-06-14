package com.testlogon.android.data.webrtc

/**
 * AND-290 — domain (DTO-free) signaling messages.
 *
 * A small sealed hierarchy the PeerConnection wrapper produces/consumes. The transport serializes these
 * to the verified wire envelopes ([CallSignalingInDto] / [BroadcastWebRtcOfferRequestDto]) and maps wire
 * replies back. Kept SDK-free and JVM-testable.
 */
sealed interface SignalingMessage {
    /** SDP offer (host -> SFU, or caller -> callee). */
    data class Offer(val sdp: SdpDescription) : SignalingMessage

    /** SDP answer (SFU -> host, or callee -> caller). */
    data class Answer(val sdp: SdpDescription) : SignalingMessage

    /** A trickled ICE candidate. */
    data class Ice(val candidate: IceCandidate) : SignalingMessage
}

/** Domain result of the host publish SDP exchange. */
data class PublishAnswer(
    val sessionId: String,
    val inputId: String,
    val answer: SdpDescription,
)

/** Domain result of a 1:1 call signaling send ack. */
data class SignalingAck(
    val eventId: String,
    val callId: String,
    val deliveredTo: String,
    val status: SignalingStatus,
)

enum class SignalingStatus { DELIVERED, DUPLICATE, UNKNOWN }

/** The dotted wire `type` discriminator for the 1:1 call signaling envelope. */
internal fun SignalingMessage.callWireType(): String = when (this) {
    is SignalingMessage.Offer -> "webrtc.offer"
    is SignalingMessage.Answer -> "webrtc.answer"
    is SignalingMessage.Ice -> "webrtc.ice_candidate"
}

/** Builds the `payload` object for the 1:1 call envelope (SDP -> {sdp,type}; ICE -> candidate fields). */
internal fun SignalingMessage.callPayload(): Map<String, Any?> = when (this) {
    is SignalingMessage.Offer -> mapOf("sdp" to sdp.sdp, "type" to sdp.type.wire())
    is SignalingMessage.Answer -> mapOf("sdp" to sdp.sdp, "type" to sdp.type.wire())
    is SignalingMessage.Ice -> mapOf(
        "candidate" to candidate.candidate,
        "sdpMid" to candidate.sdpMid,
        "sdpMLineIndex" to candidate.sdpMLineIndex,
    )
}

/** Lowercase libwebrtc SDP type string. */
internal fun SdpType.wire(): String = when (this) {
    SdpType.OFFER -> "offer"
    SdpType.ANSWER -> "answer"
    SdpType.PRANSWER -> "pranswer"
}

internal fun String?.toSignalingStatus(): SignalingStatus = when (this?.lowercase()) {
    "delivered" -> SignalingStatus.DELIVERED
    "duplicate" -> SignalingStatus.DUPLICATE
    else -> SignalingStatus.UNKNOWN
}
