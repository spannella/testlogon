package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-315 — Retrofit interface + wire DTOs for the host MONETIZATION surface: the small tip-config editor
 * and the private-show request -> accept -> active -> end lifecycle.
 *
 * Verified against the broadcast/sessions/{id}/... contract (see the AND-315 ticket): cookies /
 * Authorization / X-CSRF-Token are attached by the shared core-network interceptor chain, so this interface
 * stays header-agnostic. Paths are relative (no leading slash) and resolve against the shared Retrofit base.
 *
 * SCOPE (intentionally SMALL): tip-config is ONLY {tip_enabled, tip_min_cents, tip_max_cents}. There is NO
 * GET tips/config and NO tip-menu / currency / custom-bounds / goal-linkage endpoint — they are NOT modeled
 * here. The current tip values are READ from GET session ([BroadcastApi.getSession] returns the same shape).
 * The private-show rate is set by the VIEWER and is read-only to the host.
 *
 * Real-time is POLLING (no private-show SSE): the ViewModel polls [listPrivateRequests] + [getPrivateStatus].
 * [declinePrivateRequest] returns an empty / {ok} body, so it is typed [Response]<[Unit]> and treated as
 * success-by-isSuccessful (Moshi would throw EOF on an empty body).
 */
interface BroadcastMonetizationApi {

    // ---- TIP CONFIG (small) ----

    /**
     * PATCH the host tip-config. The response is the FULL [BroadcastSessionDto] (the persisted tip fields are
     * read back from it). All body fields are optional partial updates.
     */
    @PATCH("broadcast/sessions/{sessionId}/tips/config")
    suspend fun patchTipConfig(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastTipConfigInDto,
    ): BroadcastSessionDto

    // ---- PRIVATE SHOW (the real feature) ----

    /** List pending / active private-show requests for the session. */
    @GET("broadcast/sessions/{sessionId}/private/requests")
    suspend fun listPrivateRequests(
        @Path("sessionId") sessionId: String,
    ): PrivateRequestListDto

    /** The host's current private-show status (drives rehydration on screen start + the poll fold). */
    @GET("broadcast/sessions/{sessionId}/private/status")
    suspend fun getPrivateStatus(
        @Path("sessionId") sessionId: String,
    ): PrivateStatusDto

    /** Accept a pending request, choosing how the public stream behaves ("pause" | "end" | "continue"). */
    @POST("broadcast/sessions/{sessionId}/private/{requestId}/accept")
    suspend fun acceptPrivateRequest(
        @Path("sessionId") sessionId: String,
        @Path("requestId") requestId: String,
        @Body body: PrivateRequestAcceptInDto,
    ): PrivateAcceptDto

    /** Decline a pending request. Returns an {ok} ack or an empty 200 -> [Response]<[Unit]>. */
    @POST("broadcast/sessions/{sessionId}/private/{requestId}/decline")
    suspend fun declinePrivateRequest(
        @Path("sessionId") sessionId: String,
        @Path("requestId") requestId: String,
    ): Response<Unit>

    /** End an ACTIVE private show. Note: keyed by the PRIVATE_SESSION_ID, NOT the request id. */
    @POST("broadcast/sessions/{sessionId}/private/{privateId}/end")
    suspend fun endPrivateSession(
        @Path("sessionId") sessionId: String,
        @Path("privateId") privateId: String,
    ): PrivateSessionEndDto
}

// ---- TIP CONFIG DTOs ----

/**
 * AND-315 — partial tip-config update body. Each field is optional (null = leave unchanged). Cents bounds
 * (100..100000) are enforced CLIENT-side before the call and SERVER-side (422 otherwise).
 */
@JsonClass(generateAdapter = true)
data class BroadcastTipConfigInDto(
    @Json(name = "tip_enabled") val tipEnabled: Boolean? = null,
    @Json(name = "tip_min_cents") val tipMinCents: Long? = null,
    @Json(name = "tip_max_cents") val tipMaxCents: Long? = null,
)

// ---- PRIVATE SHOW DTOs ----

/** Envelope for the private-requests list. */
@JsonClass(generateAdapter = true)
data class PrivateRequestListDto(
    @Json(name = "requests") val requests: List<PrivateRequestDto> = emptyList(),
)

/**
 * A single private-show request. Viewer identity is FLAT (viewer_id / viewer_display_name), NOT nested.
 * Timestamps are epoch-SECOND ints. There is NO expires_at field. total_billed_cents defaults to 0.
 */
@JsonClass(generateAdapter = true)
data class PrivateRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "private_session_id") val privateSessionId: String? = null,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "viewer_id") val viewerId: String = "",
    @Json(name = "viewer_display_name") val viewerDisplayName: String? = null,
    @Json(name = "rate_per_minute_cents") val ratePerMinuteCents: Long = 0,
    @Json(name = "status") val status: String = "",
    @Json(name = "behavior") val behavior: String? = null,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "max_duration_minutes") val maxDurationMinutes: Int? = null,
    @Json(name = "requested_at") val requestedAt: Long = 0,
    @Json(name = "accepted_at") val acceptedAt: Long? = null,
    @Json(name = "started_at") val startedAt: Long? = null,
    @Json(name = "ended_at") val endedAt: Long? = null,
    @Json(name = "ended_by") val endedBy: String? = null,
    @Json(name = "total_billed_cents") val totalBilledCents: Long = 0,
)

/** The host's current private-show status. All identity fields are optional (absent when idle). */
@JsonClass(generateAdapter = true)
data class PrivateStatusDto(
    @Json(name = "status") val status: String = "",
    @Json(name = "request_id") val requestId: String? = null,
    @Json(name = "private_session_id") val privateSessionId: String? = null,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "viewer_id") val viewerId: String? = null,
    @Json(name = "viewer_display_name") val viewerDisplayName: String? = null,
    @Json(name = "rate_per_minute_cents") val ratePerMinuteCents: Long? = null,
    @Json(name = "behavior") val behavior: String? = null,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "started_at") val startedAt: Long? = null,
)

/** Accept request body: how the public stream behaves during the private show. */
@JsonClass(generateAdapter = true)
data class PrivateRequestAcceptInDto(
    @Json(name = "behavior") val behavior: String,
)

/** The accept response: the started private session. */
@JsonClass(generateAdapter = true)
data class PrivateAcceptDto(
    @Json(name = "private_session_id") val privateSessionId: String = "",
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "behavior") val behavior: String? = null,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "rate_per_minute_cents") val ratePerMinuteCents: Long = 0,
    @Json(name = "started_at") val startedAt: Long? = null,
)

/** The end response: the authoritative private-show summary (server billing wins over the client estimate). */
@JsonClass(generateAdapter = true)
data class PrivateSessionEndDto(
    @Json(name = "private_session_id") val privateSessionId: String = "",
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "duration_seconds") val durationSeconds: Int = 0,
    @Json(name = "total_billed_cents") val totalBilledCents: Long = 0,
    @Json(name = "ended_by") val endedBy: String? = null,
)
