package com.testlogon.android.data.vod.rental

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-192 — Retrofit interface + wire DTOs for the time-boxed VOD rental flow.
 *
 * Dedicated to the rental feature (separate from the catalog [com.testlogon.android.data.vod.VodApi]).
 * Paths are relative (shared base URL); cookies, Authorization: Bearer and X-CSRF-Token are attached by
 * the core-network interceptor chain. Reads (status/access/list) are idempotent GETs; start/playback/
 * playback-complete are POSTs and are NEVER auto-retried by the network layer (avoid double-charge).
 *
 * Verified contract (reference/src/api/endpoints/vodRental.ts; openapi.index.txt + openapi.pretty.json):
 *  - POST ui/vod/rental/{video_id}/start             req=VodRentalStartIn  -> VodRentalStartOut
 *  - GET  ui/vod/rental/{video_id}/status                                  -> VodRentalStatusOut
 *  - GET  ui/vod/rental/{video_id}/access                                  -> VodRentalAccessOut
 *  - POST ui/vod/rental/{video_id}/playback                               -> VodRentalPlaybackOut
 *  - POST ui/vod/rental/{video_id}/playback-complete                      -> VodRentalConsumeOut
 *  - GET  ui/vod/rental/list  (limit)                                      -> VodRentalListOut
 *
 * `tier` is constrained to ^(rental|view_once)$ (NOT quality labels). `expires_at` is nullable epoch
 * SECONDS. `views_remaining` defaults to -1 (unlimited within the window); the gate uses != 0.
 */
interface VodRentalApi {

    @POST("ui/vod/rental/{video_id}/start")
    suspend fun start(
        @Path("video_id") videoId: String,
        @Body body: VodRentalStartInDto,
    ): VodRentalStartOutDto

    @GET("ui/vod/rental/{video_id}/status")
    suspend fun status(@Path("video_id") videoId: String): VodRentalStatusOutDto

    @GET("ui/vod/rental/{video_id}/access")
    suspend fun access(@Path("video_id") videoId: String): VodRentalAccessOutDto

    @POST("ui/vod/rental/{video_id}/playback")
    suspend fun playback(@Path("video_id") videoId: String): VodRentalPlaybackOutDto

    @POST("ui/vod/rental/{video_id}/playback-complete")
    suspend fun playbackComplete(@Path("video_id") videoId: String): VodRentalConsumeOutDto

    @GET("ui/vod/rental/list")
    suspend fun list(@Query("limit") limit: Int = RENTAL_LIST_LIMIT): VodRentalListOutDto

    companion object {
        const val RENTAL_LIST_LIMIT = 50

        /** Verified pattern values for VodRentalStartIn.tier. */
        const val TIER_RENTAL = "rental"
        const val TIER_VIEW_ONCE = "view_once"
    }
}

// ---- Request DTOs ----

/** VodRentalStartIn — `tier` required (^(rental|view_once)$); duration sent only for tier=rental. */
@JsonClass(generateAdapter = true)
data class VodRentalStartInDto(
    @Json(name = "tier") val tier: String,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "rental_duration_hours") val rentalDurationHours: Int? = null,
)

// ---- Response DTOs (tolerant defaults; only the schema-required fields are non-null) ----

/** VodRentalStartOut — required: video_id, rental_id, tier. */
@JsonClass(generateAdapter = true)
data class VodRentalStartOutDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "rental_id") val rentalId: String,
    @Json(name = "tier") val tier: String,
    @Json(name = "already_active") val alreadyActive: Boolean = false,
    @Json(name = "started") val started: Boolean = false,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "amount_cents") val amountCents: Int = 0,
    @Json(name = "duration_hours") val durationHours: Int? = null,
)

/** VodRentalStatusOut — only video_id required; all else has server defaults. `reason` is free-form. */
@JsonClass(generateAdapter = true)
data class VodRentalStatusOutDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "rental_id") val rentalId: String = "",
    @Json(name = "tier") val tier: String = "",
    @Json(name = "amount_cents") val amountCents: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "started_at") val startedAt: Long = 0L,
    @Json(name = "duration_hours") val durationHours: Int = 0,
    @Json(name = "active") val active: Boolean = false,
    @Json(name = "reason") val reason: String = "not_rented",
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "remaining_seconds") val remainingSeconds: Long = 0L,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "started") val started: Boolean = false,
)

/** VodRentalAccessOut — `active` required; the lightweight gate-check shape. */
@JsonClass(generateAdapter = true)
data class VodRentalAccessOutDto(
    @Json(name = "active") val active: Boolean = false,
    @Json(name = "tier") val tier: String? = null,
    @Json(name = "reason") val reason: String = "not_rented",
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "remaining_seconds") val remainingSeconds: Long = 0L,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "rental_id") val rentalId: String? = null,
    @Json(name = "started") val started: Boolean = false,
)

/** VodRentalPlaybackOut — required: video_id, playback_url, access. `mode` default "dev". */
@JsonClass(generateAdapter = true)
data class VodRentalPlaybackOutDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "playback_url") val playbackUrl: String,
    @Json(name = "access") val access: VodRentalAccessOutDto,
    @Json(name = "manifest_key") val manifestKey: String? = null,
    @Json(name = "mode") val mode: String? = "dev",
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "token_expires_at") val tokenExpiresAt: Long = 0L,
)

/** VodRentalConsumeOut — only `ok` required. */
@JsonClass(generateAdapter = true)
data class VodRentalConsumeOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "tier") val tier: String = "",
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "consumed") val consumed: Boolean = false,
)

/** VodRentalListOut — { items: VodRentalStatusOut[] }. */
@JsonClass(generateAdapter = true)
data class VodRentalListOutDto(
    @Json(name = "items") val items: List<VodRentalStatusOutDto> = emptyList(),
)
