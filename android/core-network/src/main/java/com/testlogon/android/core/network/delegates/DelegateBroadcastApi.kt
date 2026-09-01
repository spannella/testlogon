package com.testlogon.android.core.network.delegates

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-360 - Retrofit interface for the delegate-PATH BROADCAST surface (manage-as-creator broadcast).
 *
 * ATTRIBUTION IS THE PATH: the managed creator id is the {creatorId} @Path segment, NOT a header. These
 * endpoints are DISTINCT from the self broadcast endpoints. Paths have NO leading slash. The shared CSRF /
 * Bearer / 401-refresh interceptors already cover these calls (NO new header interceptor). All calls are
 * suspend; mutations return Response of Unit (empty / 204 bodies) folded by isSuccessful; the READ calls
 * (moderators / bans / moderation-log) return BARE ARRAYS.
 *
 * PERMISSION SPLIT: start / stop / schedule are gated by broadcast_control; the moderation actions
 * (mute / ban / unban / pin / unpin / delete / announce / moderator-register) + the read lists by
 * broadcast_moderate. There is NO broadcast_operate / broadcast_publish permission. @Path tokens are
 * EXACTLY {creatorId} / {sid} / {mid} / {uid}. Mirrors the web delegateBroadcast.ts surface 1:1.
 */
interface DelegateBroadcastApi {

    // ---- Broadcast control (broadcast_control) ----

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

    // ---- Chat moderation (broadcast_moderate) ----

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

    /** UNBAN a viewer from the managed creator's broadcast session (gated by broadcast_moderate). */
    @DELETE("ui/broadcast/delegate/{creatorId}/sessions/{sid}/ban/{uid}")
    suspend fun unbanViewer(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Path("uid") uid: String,
    ): Response<Unit>

    /** POST an ANNOUNCEMENT in the managed creator's broadcast chat (gated by broadcast_moderate). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/announcement")
    suspend fun postAnnouncement(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Body body: DelegatedAnnouncementIn,
    ): Response<Unit>

    /** PIN a chat message in the managed creator's broadcast session (gated by broadcast_moderate). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/chat/{mid}/pin")
    suspend fun pinMessage(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Path("mid") mid: String,
    ): Response<Unit>

    /** UNPIN a chat message in the managed creator's broadcast session (gated by broadcast_moderate). */
    @DELETE("ui/broadcast/delegate/{creatorId}/sessions/{sid}/chat/{mid}/pin")
    suspend fun unpinMessage(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Path("mid") mid: String,
    ): Response<Unit>

    /** DELETE a chat message from the managed creator's broadcast session (gated by broadcast_moderate). */
    @DELETE("ui/broadcast/delegate/{creatorId}/sessions/{sid}/chat/{mid}")
    suspend fun deleteChatMessage(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Path("mid") mid: String,
    ): Response<Unit>

    // ---- Moderator management (broadcast_moderate) ----

    /** REGISTER the caller as an active moderator for a broadcast session (gated by broadcast_moderate). */
    @Headers("Content-Type: application/json")
    @POST("ui/broadcast/delegate/{creatorId}/sessions/{sid}/moderator/register")
    suspend fun registerModerator(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
    ): Response<Unit>

    /** LIST active moderators for a broadcast session as a BARE ARRAY (gated by broadcast_moderate). */
    @GET("ui/broadcast/delegate/{creatorId}/sessions/{sid}/moderators")
    suspend fun listModerators(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
    ): List<DelegatedBroadcastModeratorOut>

    /** LIST banned viewers for a broadcast session as a BARE ARRAY (gated by broadcast_moderate). */
    @GET("ui/broadcast/delegate/{creatorId}/sessions/{sid}/bans")
    suspend fun listBans(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
    ): List<DelegatedBroadcastBanOut>

    /** GET the moderation action log for a broadcast session as a BARE ARRAY (gated by broadcast_moderate). */
    @GET("ui/broadcast/delegate/{creatorId}/sessions/{sid}/moderation-log")
    suspend fun getModerationLog(
        @Path("creatorId") creatorId: String,
        @Path("sid") sid: String,
        @Query("limit") limit: Int = 100,
    ): List<DelegatedBroadcastModLogEntry>
}
