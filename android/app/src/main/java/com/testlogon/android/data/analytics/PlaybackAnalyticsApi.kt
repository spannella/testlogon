package com.testlogon.android.data.analytics

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-171 §5.1 — the VERIFIED playback-analytics contract. Two real mechanisms, no JSON telemetry
 * body; reuses the shared authenticated transport (cookies + X-CSRF-Token).
 *
 *  - Content / VOD: one-shot `POST /ui/videos/{video_id}/view` -> ViewRecordOut. No body.
 *  - Broadcast / live: `viewers/join` -> `viewers/heartbeat?viewer_id=` -> `viewers/leave?viewer_id=`.
 *    `viewer_id` is a QUERY param (verified web: viewerHeartbeat posts null body + params viewer_id).
 *
 * There is NO `next_interval_ms` and NO server `stop` field in any response (AND-171 §16 items 8/9).
 */
interface PlaybackAnalyticsApi {

    // Content / VOD — one-shot, no body.
    @POST("ui/videos/{videoId}/view")
    suspend fun recordVideoView(@Path("videoId") videoId: String): Response<ViewRecordDto>

    // Live broadcast viewer lifecycle — viewer_id is a QUERY param, no body.
    @POST("broadcast/sessions/{sessionId}/viewers/join")
    suspend fun viewerJoin(@Path("sessionId") sessionId: String): Response<ViewerJoinDto>

    @POST("broadcast/sessions/{sessionId}/viewers/heartbeat")
    suspend fun viewerHeartbeat(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<ViewerHeartbeatDto>

    @POST("broadcast/sessions/{sessionId}/viewers/leave")
    suspend fun viewerLeave(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<ViewerLeaveDto>
}

/** ViewRecordOut — `{ view_count, is_new_view }`. */
@JsonClass(generateAdapter = true)
data class ViewRecordDto(
    @Json(name = "view_count") val viewCount: Int,
    @Json(name = "is_new_view") val isNewView: Boolean,
)

/** ViewerJoinOut — `{ viewer_id, session_id, viewer_count }`. */
@JsonClass(generateAdapter = true)
data class ViewerJoinDto(
    @Json(name = "viewer_id") val viewerId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "viewer_count") val viewerCount: Int,
)

/** ViewerHeartbeatOut — `{ ok, viewer_count }`. */
@JsonClass(generateAdapter = true)
data class ViewerHeartbeatDto(
    val ok: Boolean,
    @Json(name = "viewer_count") val viewerCount: Int,
)

/** `viewers/leave` 200 body — `{ ok, viewer_count }` (also accepts a bare empty body). */
@JsonClass(generateAdapter = true)
data class ViewerLeaveDto(
    val ok: Boolean = true,
    @Json(name = "viewer_count") val viewerCount: Int = 0,
)
