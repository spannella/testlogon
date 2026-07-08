package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ADV FEATURE 1 (broadcast live pre-roll) — Retrofit interface + wire DTOs for the VIEWER-side broadcast
 * ad surface (previously OUT OF SCOPE; AND-316 shipped only the host control plane).
 *
 * Contract (app/routers/broadcast_ads.py):
 *  - POST broadcast/sessions/{sessionId}/ad-join -> BroadcastJoinOut { pre_roll?, ad_free, ... }. The
 *    pre-roll (if the platform + session have pre-roll enabled AND the viewer is not ad-free / the
 *    broadcaster themselves) carries the served creative + the per-serve ad_click_id minted by serve_ad
 *    (surface=broadcast_preroll, content_owner=broadcaster).
 *  - POST broadcast/sessions/{sessionId}/ads/{creativeId}/track?event=&ad_click_id=&view_time_ms= records
 *    the impression / complete / skip. On impression|complete the backend charges the advertiser (CPM,
 *    funds-guarded, idempotent per broadcast_preroll:{ad_click_id}) and credits the BROADCASTER 70/30.
 *
 * Paths are relative to the shared Retrofit base; the core-network interceptor chain attaches the UI
 * session cookie / Bearer / CSRF (the routes are behind require_ui_session).
 */
interface BroadcastViewerAdApi {

    @POST("broadcast/sessions/{sessionId}/ad-join")
    suspend fun adJoin(@Path("sessionId") sessionId: String): BroadcastAdJoinDto

    @POST("broadcast/sessions/{sessionId}/ads/{creativeId}/track")
    suspend fun trackAdEvent(
        @Path("sessionId") sessionId: String,
        @Path("creativeId") creativeId: String,
        @Query("event") event: String,
        @Query("ad_click_id") adClickId: String,
        @Query("slot_type") slotType: String = "pre_roll",
        @Query("view_time_ms") viewTimeMs: Int = 0,
    ): BroadcastAdEventOutDto
}

/** BroadcastJoinOut — the viewer ad-join envelope. */
@JsonClass(generateAdapter = true)
data class BroadcastAdJoinDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "stream_url") val streamUrl: String? = null,
    @Json(name = "pre_roll") val preRoll: BroadcastPreRollDto? = null,
    @Json(name = "ad_free") val adFree: Boolean = false,
    @Json(name = "mid_roll_skip_after_seconds") val midRollSkipAfterSeconds: Int = 15,
)

/** PreRollOut — the served pre-roll creative + its per-serve attribution id. */
@JsonClass(generateAdapter = true)
data class BroadcastPreRollDto(
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "format") val format: String = "image",
    @Json(name = "video_url") val videoUrl: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "cta_url") val ctaUrl: String? = null,
    @Json(name = "skip_after_seconds") val skipAfterSeconds: Int = 5,
    @Json(name = "ad_click_id") val adClickId: String = "",
)

/** AdEventOut — the track ack. */
@JsonClass(generateAdapter = true)
data class BroadcastAdEventOutDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "event_type") val eventType: String = "",
    @Json(name = "fraud_flagged") val fraudFlagged: Boolean = false,
)
