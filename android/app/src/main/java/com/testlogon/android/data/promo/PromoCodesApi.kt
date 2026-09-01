package com.testlogon.android.data.promo

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-266 — Retrofit interface + Moshi DTOs for the real promo-codes surface.
 *
 * Verified against reference/openapi.index.txt (lines 1754..1760) and the live schema
 * (components.schemas.PromoCodeOut / PromoCodeCreateIn / PromoCodeListOut / PromoDeactivateOut) +
 * reference/src/api/endpoints/promoCodes.ts. All paths are under /ui/promo-codes. The list endpoint is
 * NOT paginated (no cursor/limit input); the full items[] is returned in one shot. discount_value /
 * max_uses / etc. are integers; discount_value is percent (percentage) or cents (fixed_amount). Timestamps
 * are epoch SECONDS. create() POSTs PromoCodeCreateIn (code REQUIRED 3..30 chars; discount_type REQUIRED)
 * and is a plain CRUD mutation (no charge). redeem() is an internal/post-payment call (free-form body).
 *
 * Endpoint citations:
 *  - GET    ui/promo-codes            L1754 (PromoCodeListOut)
 *  - POST   ui/promo-codes            L1755 (201 PromoCodeOut)
 *  - POST   ui/promo-codes/redeem     L1756 (internal/post-payment; untyped body+resp)
 *  - DELETE ui/promo-codes/{code_id}  L1758 (PromoDeactivateOut)
 *  - GET    ui/promo-codes/{code_id}  L1759 (PromoCodeStatsOut)
 *
 * Session cookies, Authorization Bearer and X-CSRF-Token (required for the mutations) are attached by
 * core-network interceptors; operator-only params are deliberately NOT sent.
 */
interface PromoCodesApi {

    @GET("ui/promo-codes")
    suspend fun list(): PromoCodeListDto

    @POST("ui/promo-codes")
    suspend fun create(@Body body: CreatePromoRequestDto): PromoCodeDto

    @POST("ui/promo-codes/redeem")
    suspend fun redeem(@Body body: RedeemPromoRequestDto): RedeemPromoResponseDto

    @POST("ui/promo-codes/validate")
    suspend fun validate(@Body body: ValidatePromoRequestDto): PromoValidateDto

    @DELETE("ui/promo-codes/{code_id}")
    suspend fun deactivate(@Path("code_id") codeId: String): PromoDeactivateDto
}

// ---- DTOs (AND-266) ----

@JsonClass(generateAdapter = true)
data class PromoCodeDto(
    @Json(name = "code_id") val codeId: String,
    val code: String,
    @Json(name = "discount_type") val discountType: String,
    @Json(name = "discount_value") val discountValue: Int = 0,
    @Json(name = "free_trial_days") val freeTrialDays: Int = 0,
    @Json(name = "applies_to") val appliesTo: List<String> = emptyList(),
    @Json(name = "min_purchase_cents") val minPurchaseCents: Int = 0,
    @Json(name = "max_uses") val maxUses: Int = 0,
    @Json(name = "max_uses_per_user") val maxUsesPerUser: Int = 1,
    @Json(name = "current_uses") val currentUses: Int = 0,
    val active: Boolean = true,
    @Json(name = "expires_at") val expiresAt: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "creator_user_id") val creatorUserId: String = "",
)

@JsonClass(generateAdapter = true)
data class PromoCodeListDto(
    val items: List<PromoCodeDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreatePromoRequestDto(
    val code: String,
    @Json(name = "discount_type") val discountType: String,
    @Json(name = "discount_value") val discountValue: Int = 0,
    @Json(name = "free_trial_days") val freeTrialDays: Int = 0,
    @Json(name = "applies_to") val appliesTo: List<String> = listOf("subscription"),
    @Json(name = "min_purchase_cents") val minPurchaseCents: Int = 0,
    @Json(name = "max_uses") val maxUses: Int = 0,
    @Json(name = "max_uses_per_user") val maxUsesPerUser: Int = 1,
    @Json(name = "expires_at") val expiresAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class RedeemPromoRequestDto(
    @Json(name = "code_id") val codeId: String,
    @Json(name = "original_price_cents") val originalPriceCents: Int,
    @Json(name = "final_price_cents") val finalPriceCents: Int,
    @Json(name = "checkout_type") val checkoutType: String,
    @Json(name = "checkout_item_id") val checkoutItemId: String? = null,
)

@JsonClass(generateAdapter = true)
data class RedeemPromoResponseDto(
    val ok: Boolean = false,
    @Json(name = "redeemed_at") val redeemedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class PromoDeactivateDto(
    val ok: Boolean = true,
    @Json(name = "code_id") val codeId: String = "",
    val active: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class ValidatePromoRequestDto(
    val code: String,
    @Json(name = "checkout_type") val checkoutType: String,
    @Json(name = "item_price_cents") val itemPriceCents: Int,
    @Json(name = "creator_user_id") val creatorUserId: String,
)

@JsonClass(generateAdapter = true)
data class PromoValidateDto(
    val valid: Boolean = false,
    @Json(name = "code_id") val codeId: String? = null,
    @Json(name = "discount_type") val discountType: String? = null,
    @Json(name = "discount_cents") val discountCents: Int = 0,
    @Json(name = "discount_pct") val discountPct: Int? = null,
    @Json(name = "original_price_cents") val originalPriceCents: Int = 0,
    @Json(name = "final_price_cents") val finalPriceCents: Int = 0,
    @Json(name = "free_trial_days") val freeTrialDays: Int = 0,
    @Json(name = "error_code") val errorCode: String? = null,
    val message: String? = null,
)
