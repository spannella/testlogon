package com.testlogon.android.data.call

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-295 — dedicated Retrofit interface for the 1:1 call CONTROL PLANE.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * Authorization / X-CSRF-Token (on the POST/PATCH mutations) are attached by the core-network interceptor
 * chain — this interface stays header-agnostic (the OpenAPI authorization/X-SESSION-ID header params are
 * server/transport concerns and are NOT modeled, matching the AuthApi decision).
 *
 * Each method returns the raw success DTO body and throws retrofit2.HttpException on non-2xx; the wrapping
 * into ApiResult (catching HttpException / JsonDataException / JsonEncodingException / IOException) is done
 * in [CallRepository], mirroring SignalingRepository/IceServersRepository.
 *
 * The signaling send (POST .../{callId}/signal) and TURN fetch (POST .../{callId}/turn-credentials) are
 * NOT redefined here: they are owned by AND-290 [com.testlogon.android.data.webrtc.SignalingApi] /
 * AND-291 [com.testlogon.android.data.webrtc.IceServersApi] and are REUSED by the call feature.
 *
 * Endpoints verified against reference/openapi.index.txt L399-407 (control plane) and L1298 (history).
 */
interface CallApi {

    /** POST /messaging/messages/calls/invite — start a 1:1 call. openapi.index.txt L399. */
    @POST("messaging/messages/calls/invite")
    suspend fun invite(@Body body: CallInviteInDto): CallInviteOutDto

    /** POST /messaging/messages/calls/{call_id}/accept. openapi.index.txt L400. */
    @POST("messaging/messages/calls/{callId}/accept")
    suspend fun accept(
        @Path("callId") callId: String,
        @Body body: CallAcceptInDto = CallAcceptInDto(),
    ): CallActionOutDto

    /** POST /messaging/messages/calls/{call_id}/decline. openapi.index.txt L402. */
    @POST("messaging/messages/calls/{callId}/decline")
    suspend fun decline(
        @Path("callId") callId: String,
        @Body body: CallDeclineInDto = CallDeclineInDto(),
    ): CallActionOutDto

    /** POST /messaging/messages/calls/{call_id}/end. openapi.index.txt L403. */
    @POST("messaging/messages/calls/{callId}/end")
    suspend fun end(
        @Path("callId") callId: String,
        @Body body: CallEndInDto = CallEndInDto(),
    ): CallActionOutDto

    /** POST /messaging/messages/calls/{call_id}/timeout. openapi.index.txt L406. */
    @POST("messaging/messages/calls/{callId}/timeout")
    suspend fun timeout(
        @Path("callId") callId: String,
        @Body body: CallTimeoutInDto = CallTimeoutInDto(),
    ): CallActionOutDto

    /** PATCH /messaging/messages/calls/{call_id}/heartbeat (billing keepalive). openapi.index.txt L404. */
    @PATCH("messaging/messages/calls/{callId}/heartbeat")
    suspend fun heartbeat(
        @Path("callId") callId: String,
        @Body body: HeartbeatInDto = HeartbeatInDto(),
    ): HeartbeatOutDto

    /** GET /messaging/messages/calls/{call_id}/billing (idempotent read). openapi.index.txt L401. */
    @GET("messaging/messages/calls/{callId}/billing")
    suspend fun billing(@Path("callId") callId: String): CallBillingStatusOutDto

    /** GET /ui/calls/history (paged, cursor + limit). openapi.index.txt L1298. */
    @GET("ui/calls/history")
    suspend fun history(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CallHistoryResponseDto
}
