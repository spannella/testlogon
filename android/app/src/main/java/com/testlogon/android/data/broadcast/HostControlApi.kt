package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-309 — Retrofit interface for the host LIVE lifecycle control plane (start / stop / resume /
 * reschedule) plus the read-only health poll for a broadcast session.
 *
 * Verified against the broadcast sessions control plane (base broadcast/sessions/{id}/...). Paths are
 * relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * Authorization: Bearer / X-CSRF-Token are attached project-wide by the core-network interceptor chain
 * (SessionAuthenticator + CsrfInterceptor + PersistentCookieJar) — this interface stays header-agnostic.
 *
 * KEY WIRE FACTS (do not drift):
 *  - start / stop take a SessionActionDto body ({reason}); resume takes NO body; reschedule takes a
 *    RescheduleRequest body whose scheduled_at is an INTEGER epoch SECONDS (NOT ISO, NOT scheduled_start_at).
 *  - all four lifecycle calls return the FULL session (BroadcastSessionOut) -> reuse [BroadcastSessionDto].
 *  - the terminal stop state is "stopped" (NOT "ended").
 *  - health returns BroadcastHealthOut; there is NO level/ingest_connected/rtt_ms on the wire (client-derived).
 */
interface HostControlApi {

    /** Start (go-live) [sessionId]. Returns 202 with the live session (status "live", started_at ISO). */
    @POST("broadcast/sessions/{sessionId}/start")
    suspend fun start(
        @Path("sessionId") sessionId: String,
        @Body body: SessionActionDto,
    ): BroadcastSessionDto

    /** Stop [sessionId]. Returns 202 with the terminal session (status "stopped", stopped_at ISO). */
    @POST("broadcast/sessions/{sessionId}/stop")
    suspend fun stop(
        @Path("sessionId") sessionId: String,
        @Body body: SessionActionDto,
    ): BroadcastSessionDto

    /** Resume [sessionId] (no body). Returns 200 with the session. */
    @POST("broadcast/sessions/{sessionId}/resume")
    suspend fun resume(@Path("sessionId") sessionId: String): BroadcastSessionDto

    /** Reschedule [sessionId] to a future epoch-SECOND instant. Returns 200 with the session. */
    @POST("broadcast/sessions/{sessionId}/reschedule")
    suspend fun reschedule(
        @Path("sessionId") sessionId: String,
        @Body body: RescheduleRequest,
    ): BroadcastSessionDto

    /** Poll [sessionId] ingest/output health. Returns 200 with BroadcastHealthOut. */
    @GET("broadcast/sessions/{sessionId}/health")
    suspend fun health(@Path("sessionId") sessionId: String): BroadcastHealthDto

    /**
     * Read [sessionId]'s current full session (same BroadcastSessionOut shape as the lifecycle responses).
     * Used to load the control surface and to re-sync after a failed action.
     */
    @GET("broadcast/sessions/{sessionId}")
    suspend fun session(@Path("sessionId") sessionId: String): BroadcastSessionDto
}

/**
 * AND-309 — request body for start / stop. [reason] defaults to "operator-request" (the host tapping the
 * control). Serialized as {"reason": ...}.
 */
@JsonClass(generateAdapter = true)
data class SessionActionDto(
    @Json(name = "reason") val reason: String = "operator-request",
)

/**
 * AND-309 — request body for reschedule. [scheduledAt] is an INTEGER Unix epoch SECONDS (NOT ISO, NOT
 * scheduled_start_at); the server rejects past / under-min-lead instants with a 422.
 */
@JsonClass(generateAdapter = true)
data class RescheduleRequest(
    @Json(name = "scheduled_at") val scheduledAt: Long,
)

/**
 * AND-309 — BroadcastHealthOut wire DTO for the health poll. Field names are the EXACT wire keys. There is
 * deliberately NO level / ingest_connected / rtt_ms / uplink_kbps / fps / captured_at on the wire —
 * [HealthLevel] is CLIENT-DERIVED from [connectionQuality] in the mapper, and rttMs / ingestConnected stay
 * null because media (RTCStats) is FLAGGED (the [com.testlogon.android.data.webrtc.BroadcastPublisher] seam).
 */
@JsonClass(generateAdapter = true)
data class BroadcastHealthDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "connection_quality") val connectionQuality: String = "",
    @Json(name = "ingest_bitrate_kbps") val ingestBitrateKbps: Int = 0,
    @Json(name = "ingest_framerate") val ingestFramerate: Double = 0.0,
    @Json(name = "dropped_frames") val droppedFrames: Int = 0,
    @Json(name = "dropped_frames_pct") val droppedFramesPct: Double = 0.0,
    @Json(name = "output_errors") val outputErrors: Int = 0,
    @Json(name = "input_loss_seconds") val inputLossSeconds: Double = 0.0,
    @Json(name = "viewer_count") val viewerCount: Int = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)
