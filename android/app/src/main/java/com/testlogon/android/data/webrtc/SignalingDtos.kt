package com.testlogon.android.data.webrtc

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-290 — wire DTOs for the WebRTC signaling transport.
 *
 * Two REAL backend signaling surfaces are mapped here (verified against the staged reference):
 *
 * 1. HOST broadcast publish signaling (the path the native "Go Live" host uses):
 *    POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer
 *    req  BroadcastWebRTCOfferIn  = { sdp_offer }            (reference openapi.pretty.json L12888)
 *    resp BroadcastWebRTCOfferOut = { sdp_answer, session_id, input_id }  (L12903)
 *    Reference TS: reference/src/api/endpoints/broadcast-inputs.ts: sendWebRTCOffer().
 *    This is a single request/response SDP exchange (offer -> answer), NOT a trickled channel.
 *
 * 2. 1:1 / group CALL signaling (provided for completeness; the call feature owns it):
 *    POST /messaging/messages/calls/{call_id}/signal
 *    req  CallSignalingIn  = { type, event_id, conversation_id, recipient_user_id, nonce, sent_at,
 *                              payload }  (reference openapi.pretty.json L14117; pattern-constrained type)
 *    resp CallSignalingOut = { event_id, call_id, conversation_id, event_type, delivered_to, status }
 *                              (L14169)
 *    Reference TS: reference/src/api/endpoints/messaging.ts: sendSignalingEvent() (L1043).
 *    `sent_at` is epoch SECONDS (integer); `type` is the dotted envelope discriminator
 *    (webrtc.offer|webrtc.answer|webrtc.ice_candidate); the SDP/ICE objects nest under `payload`.
 *
 * Inbound peer signaling for the 1:1 call path arrives over the shared messaging SSE stream
 * (GET /messaging/events/stream) — out of scope for this host-broadcasting slice and NOT implemented
 * here (no dedicated /signal/events endpoint exists). Field names are snake_case via [Json]; absent
 * optionals fall back to Kotlin defaults (lenient decode).
 */

// ─── Host broadcast publish signaling (the go-live SDP exchange) ──────────────────────────────────

/** BroadcastWebRTCOfferIn — the host's SDP offer for a publish input. */
@JsonClass(generateAdapter = true)
data class BroadcastWebRtcOfferRequestDto(
    @Json(name = "sdp_offer") val sdpOffer: String,
)

/** BroadcastWebRTCOfferOut — the SFU's SDP answer. */
@JsonClass(generateAdapter = true)
data class BroadcastWebRtcAnswerDto(
    @Json(name = "sdp_answer") val sdpAnswer: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_id") val inputId: String,
)

// ─── 1:1 / group call signaling envelope ─────────────────────────────────────────────────────────

/** CallSignalingIn — flat signaling envelope; SDP/ICE goes under [payload]. */
@JsonClass(generateAdapter = true)
data class CallSignalingInDto(
    @Json(name = "type") val type: String,
    @Json(name = "event_id") val eventId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "recipient_user_id") val recipientUserId: String,
    @Json(name = "nonce") val nonce: String,
    @Json(name = "sent_at") val sentAt: Long,
    @Json(name = "payload") val payload: Map<String, Any?> = emptyMap(),
)

/** CallSignalingOut — the send acknowledgement. `status` is "delivered" | "duplicate". */
@JsonClass(generateAdapter = true)
data class CallSignalingOutDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "delivered_to") val deliveredTo: String,
    @Json(name = "status") val status: String,
)
