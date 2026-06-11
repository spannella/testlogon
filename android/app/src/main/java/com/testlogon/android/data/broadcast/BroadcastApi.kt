package com.testlogon.android.data.broadcast

import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-278 — Retrofit interface for the authenticated broadcast read surface.
 *
 * Verified against reference/src/api/endpoints/broadcast.ts + broadcastSchedule.ts + openapi.index.txt.
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * Authorization / X-CSRF-Token (sent on GETs too) are attached by the core-network interceptor chain —
 * this interface stays header-agnostic. All reads are idempotent GETs; [mintPlaybackUrl] is the one POST.
 *
 * KEY FACTS:
 *  - the list is a `?status=`/`?limit=` query on `broadcast/sessions`; the envelope is { items, has_more }
 *    (NO cursor — `limit` is the only paging lever). `status` is a free lifecycle string (live/scheduled
 *    /stopped/...), optional (omit for all). There is NO `?status=upcoming`/`ended` value.
 *  - scheduled & upcoming are DEDICATED routes returning { items, count }.
 *  - getSession returns the SAME BroadcastSessionOut shape as a list element (no richer detail object).
 *  - remind-me / viewers endpoints are owned by AND-279/AND-286 and are NOT declared here.
 */
interface BroadcastApi {

    @GET("broadcast/sessions")
    suspend fun listSessions(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
    ): BroadcastSessionListRespDto

    @GET("broadcast/sessions/scheduled")
    suspend fun listScheduledSessions(
        @Query("limit") limit: Int? = null,
    ): BroadcastScheduledListRespDto

    @GET("broadcast/sessions/upcoming")
    suspend fun listUpcomingSessions(
        @Query("limit") limit: Int? = null,
    ): BroadcastScheduledListRespDto

    @GET("broadcast/sessions/{sessionId}")
    suspend fun getSession(@Path("sessionId") sessionId: String): BroadcastSessionDto

    @POST("broadcast/sessions/{sessionId}/playback-url")
    suspend fun mintPlaybackUrl(@Path("sessionId") sessionId: String): BroadcastPlaybackUrlDto
}
