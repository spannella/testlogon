package com.testlogon.android.data.broadcast

import retrofit2.http.Body
import retrofit2.http.DELETE
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

    /**
     * T3 — PUBLIC live-discovery feed: currently-live sessions across ALL creators, for any authenticated
     * VIEWER. `broadcast/sessions?status=live` is operator-scoped (a non-operator only sees their OWN
     * sessions), so a second-user viewer could never find the host's broadcast through it. This dedicated
     * endpoint returns the same BroadcastSessionListOut = { items, has_more } shape.
     */
    @GET("broadcast/live")
    suspend fun listLiveSessions(
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

    // ---- AND-307 host (broadcasting) control-plane mutations (extends AND-278) ----

    /** Create a host session (draft). Returns the same BroadcastSessionOut superset shape. */
    @POST("broadcast/sessions")
    suspend fun createSession(@Body body: BroadcastSessionCreateInDto): BroadcastSessionDto

    /** Schedule a session for a future Unix epoch-second instant (sets name/scheduled_at/schedule_status). */
    @POST("broadcast/sessions/{sessionId}/schedule")
    suspend fun scheduleSession(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastScheduleInDto,
    ): BroadcastSessionDto

    /** Cancel a pending schedule (no body); the session returns to cancelled with cancelled_at set. */
    @POST("broadcast/sessions/{sessionId}/cancel-schedule")
    suspend fun cancelSchedule(@Path("sessionId") sessionId: String): BroadcastSessionDto

    // ---- AND-308 host broadcast INPUTS control plane (the ingest inputs) ----

    /**
     * Create an ingest input for [sessionId]. Returns the allocated input (ingest_url / stream_key /
     * AWS input ARN). Use input_type "primary" for the host's own camera/mic. Returns 201.
     */
    @POST("broadcast/sessions/{sessionId}/inputs")
    suspend fun createInput(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastInputCreateInDto,
    ): BroadcastInputCreateOutDto

    /** Activate an input (mark it the active publishing feed). No body. */
    @POST("broadcast/sessions/{sessionId}/inputs/{inputId}/activate")
    suspend fun activateInput(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    )

    /** Deactivate an input. No body. */
    @POST("broadcast/sessions/{sessionId}/inputs/{inputId}/deactivate")
    suspend fun deactivateInput(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    )

    /** Remove an input entirely. */
    @DELETE("broadcast/sessions/{sessionId}/inputs/{inputId}")
    suspend fun removeInput(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    )

    // NOTE: the per-input host-publish SDP exchange (POST .../inputs/{inputId}/webrtc-offer) is NOT
    // declared here — it ALREADY exists as SignalingApi.sendBroadcastOffer (AND-290) and is driven via
    // SignalingRepository.exchangeBroadcastOffer. AND-308 REUSES that path rather than duplicating it.
}
