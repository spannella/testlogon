package com.testlogon.android.data.call.group

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-299 — dedicated Retrofit interface for the GROUP-call CONTROL PLANE under `ui/calls/group/`.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * Authorization / X-CSRF-Token (on the POST/PATCH mutations) are attached by the core-network interceptor
 * chain — this interface stays header-agnostic (mirrors [com.testlogon.android.data.call.CallApi]).
 *
 * Each method returns the raw success DTO body and throws retrofit2.HttpException on non-2xx; the wrapping
 * into ApiResult (catching HttpException / JsonDataException / JsonEncodingException / IOException) is done
 * in [GroupCallRepository].
 */
interface GroupCallApi {

    /** POST ui/calls/group/create — start a group call (201 GroupCallOut). */
    @POST("ui/calls/group/create")
    suspend fun create(@Body body: GroupCallCreateInDto): GroupCallOutDto

    /** GET ui/calls/group/{id} — fetch a group call. */
    @GET("ui/calls/group/{id}")
    suspend fun get(@Path("id") callId: String): GroupCallOutDto

    /** GET ui/calls/group/{id}/participants — the current roster. */
    @GET("ui/calls/group/{id}/participants")
    suspend fun participants(@Path("id") callId: String): GroupCallParticipantsOutDto

    /** GET ui/calls/group/active/{conversationId} — probe for an active group call. */
    @GET("ui/calls/group/active/{conversationId}")
    suspend fun active(@Path("conversationId") conversationId: String): GroupCallActiveOutDto

    /** POST ui/calls/group/{id}/join — join the call (200 GroupCallJoinOut). */
    @POST("ui/calls/group/{id}/join")
    suspend fun join(@Path("id") callId: String): GroupCallJoinOutDto

    /** POST ui/calls/group/{id}/leave — leave the call. */
    @POST("ui/calls/group/{id}/leave")
    suspend fun leave(@Path("id") callId: String): GroupCallLeaveOutDto

    /** POST ui/calls/group/{id}/end — end the call (host). */
    @POST("ui/calls/group/{id}/end")
    suspend fun end(@Path("id") callId: String): GroupCallEndOutDto

    /** PATCH ui/calls/group/{id}/media — update local media flags. */
    @PATCH("ui/calls/group/{id}/media")
    suspend fun media(
        @Path("id") callId: String,
        @Body body: GroupCallMediaUpdateInDto,
    ): GroupCallMediaUpdateOutDto

    /** POST ui/calls/group/{id}/signal — relay an opaque signaling payload to a peer. */
    @POST("ui/calls/group/{id}/signal")
    suspend fun signal(
        @Path("id") callId: String,
        @Body body: GroupCallSignalInDto,
    ): GroupCallSignalOutDto
}
