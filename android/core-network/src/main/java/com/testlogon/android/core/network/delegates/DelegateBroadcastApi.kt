package com.testlogon.android.core.network.delegates

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-360 - Retrofit interface for the delegate-PATH BROADCAST surface (manage-as-creator broadcast).
 *
 * ATTRIBUTION IS THE PATH: the managed creator id is the {creatorId} @Path segment, NOT a header. These
 * endpoints are DISTINCT from the self broadcast endpoints. Paths have NO leading slash. The shared CSRF /
 * Bearer / 401-refresh interceptors already cover these calls (NO new header interceptor). All calls are
 * suspend; mutations return Response of Unit (empty / 204 bodies) folded by isSuccessful.
 *
 * PERMISSION SPLIT: start / stop / schedule are gated by broadcast_control; the moderation actions
 * (mute / ban / unban / pin / delete / announce) by broadcast_moderate. There is NO broadcast_operate /
 * broadcast_publish permission. @Path tokens are EXACTLY {creatorId} / {sid}. The full broadcast console
 * is owned by the broadcast epic; this models the control + a representative pair of moderation actions.
 */
interface DelegateBroadcastApi {

    /** START a managed creator's broadcast session (gated by broadcast_control). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/start")
    suspend fun startSession(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
    ): Response<Unit>

    /** STOP a managed creator's broadcast session (gated by broadcast_control). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/stop")
    suspend fun stopSession(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
    ): Response<Unit>

    /** SCHEDULE a managed creator's broadcast session (gated by broadcast_control). Lenient body / response. */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/schedule")
    suspend fun scheduleSession(
        @Path("creatorId") creatorId: String,
        @Body body: DelegatedScheduleSessionIn,
    ): Response<Unit>

    /** MUTE a viewer in the managed creator's broadcast session (gated by broadcast_moderate). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/mute")
    suspend fun muteViewer(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Body body: DelegatedModerationIn,
    ): Response<Unit>

    /** BAN a viewer from the managed creator's broadcast session (gated by broadcast_moderate). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/ban")
    suspend fun banViewer(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Body body: DelegatedModerationIn,
    ): Response<Unit>
}
