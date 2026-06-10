package com.testlogon.android.data.vod.adsupported

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-194 — Retrofit interface + wire DTOs for ad-supported (AVOD) playback.
 *
 * Verified contract (reference/src/api/endpoints/vodAdSupported.ts; openapi.index.txt + pretty.json):
 *  - GET  ui/vod/ad-supported/{video_id}/session                          -> VodAdSupportedSessionOut
 *      (read state; NO playback grant in this response)
 *  - POST ui/vod/ad-supported/{video_id}/start  req=VodAdSupportedStartIn -> VodAdSupportedStartOut
 *      (begin; returns playback_url + ad_schedule)
 *  - POST ui/vod/ad-supported/{video_id}/break  req=VodAdBreakReportIn    -> VodAdBreakReportOut
 *      (report impression|complete|skip; returns updated playback_unlocked / next_required_break_id)
 *
 * Units are integer SECONDS; ONE creative per break; slot_type is pre_roll|mid_roll|overlay (no
 * post_roll). Gating is SERVER-authoritative (playback_unlocked / next_required_break_id).
 */
interface VodAdSupportedApi {

    @GET("ui/vod/ad-supported/{video_id}/session")
    suspend fun getSession(@Path("video_id") videoId: String): VodAdSupportedSessionOutDto

    @POST("ui/vod/ad-supported/{video_id}/start")
    suspend fun start(
        @Path("video_id") videoId: String,
        @Body body: VodAdSupportedStartInDto = VodAdSupportedStartInDto(),
    ): VodAdSupportedStartOutDto

    @POST("ui/vod/ad-supported/{video_id}/break")
    suspend fun reportBreak(
        @Path("video_id") videoId: String,
        @Body body: VodAdBreakReportInDto,
    ): VodAdBreakReportOutDto

    companion object {
        const val SLOT_PRE_ROLL = "pre_roll"
        const val SLOT_MID_ROLL = "mid_roll"
        const val SLOT_OVERLAY = "overlay"

        const val EVENT_IMPRESSION = "impression"
        const val EVENT_COMPLETE = "complete"
        const val EVENT_SKIP = "skip"
    }
}

/** VodAdBreak — all fields required by the schema; one creative per break; integer seconds. */
@JsonClass(generateAdapter = true)
data class VodAdBreakDto(
    @Json(name = "break_id") val breakId: String,
    @Json(name = "slot_type") val slotType: String,
    @Json(name = "position_seconds") val positionSeconds: Int,
    @Json(name = "duration_seconds") val durationSeconds: Int,
    @Json(name = "creative_id") val creativeId: String,
    @Json(name = "creative_url") val creativeUrl: String,
    @Json(name = "creative_type") val creativeType: String,
    @Json(name = "skip_after_seconds") val skipAfterSeconds: Int,
    @Json(name = "slot_index") val slotIndex: Int,
    @Json(name = "completed") val completed: Boolean = false,
)

/** VodAdSupportedStartIn — all optional; {} acceptable. */
@JsonClass(generateAdapter = true)
data class VodAdSupportedStartInDto(
    @Json(name = "resume_position_seconds") val resumePositionSeconds: Int = 0,
)

/** VodAdSupportedSessionOut — read state (no playback grant). */
@JsonClass(generateAdapter = true)
data class VodAdSupportedSessionOutDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "status") val status: String = "active",
    @Json(name = "ad_schedule") val adSchedule: List<VodAdBreakDto> = emptyList(),
    @Json(name = "breaks_total") val breaksTotal: Int = 0,
    @Json(name = "breaks_completed") val breaksCompleted: Int = 0,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean = false,
    @Json(name = "ads_free") val adsFree: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

/** VodAdSupportedStartOut — session state + playback grant. */
@JsonClass(generateAdapter = true)
data class VodAdSupportedStartOutDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "status") val status: String = "active",
    @Json(name = "ad_schedule") val adSchedule: List<VodAdBreakDto> = emptyList(),
    @Json(name = "breaks_total") val breaksTotal: Int = 0,
    @Json(name = "breaks_completed") val breaksCompleted: Int = 0,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean = false,
    @Json(name = "ads_free") val adsFree: Boolean = false,
    @Json(name = "playback_url") val playbackUrl: String = "",
    @Json(name = "manifest_key") val manifestKey: String = "",
    @Json(name = "mode") val mode: String = "ad_supported",
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "token_expires_at") val tokenExpiresAt: Long = 0L,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

/** VodAdBreakReportIn — break_id required; event_type ^(impression|complete|skip)$ default complete. */
@JsonClass(generateAdapter = true)
data class VodAdBreakReportInDto(
    @Json(name = "break_id") val breakId: String,
    @Json(name = "event_type") val eventType: String = "complete",
)

/** VodAdBreakReportOut — updated gating state. */
@JsonClass(generateAdapter = true)
data class VodAdBreakReportOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "break_id") val breakId: String = "",
    @Json(name = "event_type") val eventType: String = "",
    @Json(name = "completed") val completed: Boolean = false,
    @Json(name = "breaks_completed") val breaksCompleted: Int = 0,
    @Json(name = "breaks_total") val breaksTotal: Int = 0,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean = false,
    @Json(name = "status") val status: String = "active",
)
