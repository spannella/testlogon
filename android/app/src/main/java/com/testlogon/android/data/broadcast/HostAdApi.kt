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
 * AND-316 — Retrofit interface + wire DTOs for the host AD-BREAK / AD-CONFIG control plane.
 *
 * SCOPE: this is the HOST control-plane only — trigger / end an ad break and edit the small ad-config
 * (pre-roll toggle + mid-roll duration + skip-after). Viewer-side ad RENDERING is OUT OF SCOPE, so there is
 * NO ad-network / IMA / ExoPlayer-ads dependency anywhere in this feature.
 *
 * Verified against the broadcast/sessions/{sessionId}/... contract: cookies / Authorization: Bearer /
 * X-CSRF-Token are attached project-wide by the core-network interceptor chain, so this interface stays
 * header-agnostic. Paths are relative (no leading slash) so they resolve against the shared Retrofit base.
 *
 * KEY WIRE FACTS (do not drift):
 *  - GET / PATCH ad-config return BroadcastAdConfigOut; PATCH sends ONLY changed fields (Moshi omits nulls).
 *  - triggerAdBreak / endAdBreak take NO body.
 *  - endAdBreak returns an untyped / {ok} body -> typed [Response]<[Unit]> and treated as
 *    success-by-isSuccessful (Moshi would throw EOF on an empty body). The ViewModel then re-reads ad-config
 *    to reconcile total_ad_breaks.
 */
interface HostAdApi {

    /** Read the current ad-config (drives the editor + the active ad-break state on screen start). */
    @GET("broadcast/sessions/{sessionId}/ad-config")
    suspend fun getAdConfig(
        @Path("sessionId") sessionId: String,
    ): Response<BroadcastAdConfigOutDto>

    /** Partial-update the ad-config; body carries ONLY the changed fields (nulls are omitted by Moshi). */
    @PATCH("broadcast/sessions/{sessionId}/ad-config")
    suspend fun updateAdConfig(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastAdConfigInDto,
    ): Response<BroadcastAdConfigOutDto>

    /** Trigger a mid-roll ad break (no body). Returns the started break. */
    @POST("broadcast/sessions/{sessionId}/ad-break")
    suspend fun triggerAdBreak(
        @Path("sessionId") sessionId: String,
    ): Response<AdBreakOutDto>

    /** End the active ad break early (no body). Returns an {ok} ack or an empty 200 -> [Response]<[Unit]>. */
    @POST("broadcast/sessions/{sessionId}/ad-break/end")
    suspend fun endAdBreak(
        @Path("sessionId") sessionId: String,
    ): Response<Unit>
}

/**
 * AND-316 — BroadcastAdConfigOut wire DTO. Field names are the EXACT wire keys. [adBreakStartedAt] is an
 * epoch-SECOND Long, nullable (absent when no break is active).
 */
@JsonClass(generateAdapter = true)
data class BroadcastAdConfigOutDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean = false,
    @Json(name = "mid_roll_ad_break_duration_seconds") val midRollAdBreakDurationSeconds: Int = 0,
    @Json(name = "mid_roll_skip_after_seconds") val midRollSkipAfterSeconds: Int = 0,
    @Json(name = "ad_break_active") val adBreakActive: Boolean = false,
    @Json(name = "ad_break_started_at") val adBreakStartedAt: Long? = null,
    @Json(name = "total_ad_breaks") val totalAdBreaks: Int = 0,
)

/**
 * AND-316 — partial ad-config update body. Each field is optional (null = leave unchanged). Only the changed
 * fields are non-null; Moshi's default (serializeNulls = false) OMITS the untouched keys from the wire body.
 * Server enforces duration 15..60 and skip-after 5..30 (422 otherwise); the client validates the same first.
 */
@JsonClass(generateAdapter = true)
data class BroadcastAdConfigInDto(
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean? = null,
    @Json(name = "mid_roll_ad_break_duration_seconds") val midRollAdBreakDurationSeconds: Int? = null,
    @Json(name = "mid_roll_skip_after_seconds") val midRollSkipAfterSeconds: Int? = null,
)

/**
 * AND-316 — AdBreakOut wire DTO from triggerAdBreak. [ok] defaults to true; [startedAt] is an epoch-SECOND
 * Long.
 */
@JsonClass(generateAdapter = true)
data class AdBreakOutDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "duration_seconds") val durationSeconds: Int = 0,
    @Json(name = "started_at") val startedAt: Long = 0L,
    @Json(name = "skip_after_seconds") val skipAfterSeconds: Int = 0,
)
