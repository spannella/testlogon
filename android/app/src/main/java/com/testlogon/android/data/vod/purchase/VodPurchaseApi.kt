package com.testlogon.android.data.vod.purchase

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-193 — Retrofit interface + wire DTOs for tiered VOD purchase (buy / own).
 *
 * Verified contract (reference/src/api/endpoints/vodPurchaseTiers.ts; openapi.index.txt + pretty.json):
 *  - GET  ui/videos/{video_id}/access                       -> VodAccessOut   (the offer / entitlement)
 *  - POST ui/videos/{video_id}/purchase  req=VodPurchaseIn  -> VodPurchaseOut (flat entitlement)
 *
 * There is NO per-tier list and NO `currency` field. The selectable "tiers" are the fixed
 * purchase_type enum (view_once|rental|permanent|download). The idempotency key travels in the BODY
 * (`idempotency_key`), NOT a header. `already_owned == true` in the 200 is the idempotent-success
 * signal (there is no 409). Timestamps are epoch-SECOND integers.
 */
interface VodPurchaseApi {

    @GET("ui/videos/{video_id}/access")
    suspend fun getAccess(@Path("video_id") videoId: String): VodAccessOutDto

    @POST("ui/videos/{video_id}/purchase")
    suspend fun purchase(
        @Path("video_id") videoId: String,
        @Body body: VodPurchaseInDto,
    ): VodPurchaseOutDto

    companion object {
        const val TYPE_VIEW_ONCE = "view_once"
        const val TYPE_RENTAL = "rental"
        const val TYPE_PERMANENT = "permanent"
        const val TYPE_DOWNLOAD = "download"
    }
}

/** VodAccessOut — required: entitled, reason. No vod_id, no currency. price_cents nullable. */
@JsonClass(generateAdapter = true)
data class VodAccessOutDto(
    @Json(name = "entitled") val entitled: Boolean = false,
    @Json(name = "purchase_available") val purchaseAvailable: Boolean = false,
    @Json(name = "price_cents") val priceCents: Long? = null,
    @Json(name = "purchase_type") val purchaseType: String = "permanent",
    @Json(name = "subscription_available") val subscriptionAvailable: Boolean = false,
    @Json(name = "subscription_upsell") val subscriptionUpsell: Boolean = false,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "download_allowed") val downloadAllowed: Boolean = false,
    @Json(name = "access_mode") val accessMode: String? = null,
    @Json(name = "ads_enabled") val adsEnabled: Boolean = false,
    @Json(name = "reason") val reason: String = "not_purchased",
)

/** VodPurchaseIn — all optional; purchase_type defaults "permanent". idempotency_key in BODY. */
@JsonClass(generateAdapter = true)
data class VodPurchaseInDto(
    @Json(name = "purchase_type") val purchaseType: String,
    @Json(name = "idempotency_key") val idempotencyKey: String?,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/** VodPurchaseOut — flat; required: video_id, already_owned, granted_at, grant_type, amount_cents. */
@JsonClass(generateAdapter = true)
data class VodPurchaseOutDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "already_owned") val alreadyOwned: Boolean,
    @Json(name = "granted_at") val grantedAt: Long,
    @Json(name = "grant_type") val grantType: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "purchase_id") val purchaseId: String = "",
    @Json(name = "purchase_type") val purchaseType: String = "permanent",
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "download_allowed") val downloadAllowed: Boolean = false,
)
