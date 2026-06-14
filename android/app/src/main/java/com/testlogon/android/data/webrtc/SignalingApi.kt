package com.testlogon.android.data.webrtc

import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-290 — dedicated Retrofit interface for the REAL WebRTC signaling send paths.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * Authorization / X-CSRF-Token (sent on POSTs) are attached by the core-network interceptor chain — this
 * interface stays header-agnostic. Verified against reference/src/api/endpoints/broadcast-inputs.ts and
 * messaging.ts + openapi.index.txt (lines 192 and 405).
 */
interface SignalingApi {

    /**
     * HOST publish SDP exchange — the native go-live path posts its local SDP offer and receives the
     * SFU's SDP answer. Single request/response (no trickle channel). openapi.index.txt L192.
     */
    @POST("broadcast/sessions/{sessionId}/inputs/{inputId}/webrtc-offer")
    suspend fun sendBroadcastOffer(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
        @Body body: BroadcastWebRtcOfferRequestDto,
    ): BroadcastWebRtcAnswerDto

    /**
     * 1:1 / group call signaling send (offer / answer / ICE under the flat envelope). Provided for the
     * call feature; the host-broadcasting go-live flow uses [sendBroadcastOffer]. openapi.index.txt L405.
     */
    @POST("messaging/messages/calls/{callId}/signal")
    suspend fun sendCallSignal(
        @Path("callId") callId: String,
        @Body body: CallSignalingInDto,
    ): CallSignalingOutDto
}
