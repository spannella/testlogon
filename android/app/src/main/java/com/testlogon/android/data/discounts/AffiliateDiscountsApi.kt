package com.testlogon.android.data.discounts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-267 — Retrofit interface + Moshi DTOs for the real affiliate-discounts surface.
 *
 * Verified against reference/openapi.index.txt (lines 799/803) and
 * reference/src/api/endpoints/adCreativeAffiliate.ts + src/api/types.ts:AdAffiliateDiscount /
 * AdAffiliateDiscountList. The OpenAPI 200 bodies are typed AdAffiliateDiscountListOut /
 * AdAffiliateDiscountOut; the frontend TypeScript types are the authoritative field shape.
 *
 * This is a READ-ONLY consumption surface: the affiliate/promo discounts attached to the caller's ad
 * creatives, each keyed by creative_id. There is NO per-discount numeric value / validity window /
 * redemption cap / enabled flag on the wire — value is the free-text promo_value_display string, and the
 * shareable link is click_through_url (verified §16 of the spec). Attach/update/remove/redeem/stats are
 * out of scope (separate endpoints, owned elsewhere). Money/charge is not involved (plain CRUD read).
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET ui/ads/affiliate/discounts                          L803 (AdAffiliateDiscountListOut) — list
 *  - GET ui/ads/affiliate/creatives/{creative_id}/discount   L799 (AdAffiliateDiscountOut) — single row
 *
 * Timestamps (created_at / updated_at) are epoch SECONDS (Long). Session cookies, Authorization Bearer and
 * X-CSRF-Token are attached by core-network interceptors; the operator-only user_sub / X-SESSION-ID /
 * X-IMPERSONATION-TOKEN params are deliberately NOT sent. The list endpoint takes no functional query
 * params (no cursor/limit — AdAffiliateDiscountListOut is a bare items[] with no pagination).
 */
interface AffiliateDiscountsApi {

    /** Affiliate/promo discounts attached to the caller's ad creatives. */
    @GET("ui/ads/affiliate/discounts")
    suspend fun listDiscounts(): AffiliateDiscountListDto

    /** Single discount keyed by creative_id (the only single-record GET; no discount-id route exists). */
    @GET("ui/ads/affiliate/creatives/{creativeId}/discount")
    suspend fun getDiscount(@Path("creativeId") creativeId: String): AffiliateDiscountDto
}

// ---- DTOs (AND-267) ----

@JsonClass(generateAdapter = true)
data class AffiliateDiscountListDto(
    val items: List<AffiliateDiscountDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AffiliateDiscountDto(
    @Json(name = "creative_id") val creativeId: String,
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "owner_sub") val ownerSub: String = "",
    @Json(name = "affiliate_code") val affiliateCode: String? = null,
    @Json(name = "promo_code") val promoCode: String? = null,
    @Json(name = "promo_value_display") val promoValueDisplay: String? = null,
    @Json(name = "click_through_url") val clickThroughUrl: String? = null,
    @Json(name = "click_count") val clickCount: Long = 0,
    @Json(name = "redemption_count") val redemptionCount: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)
