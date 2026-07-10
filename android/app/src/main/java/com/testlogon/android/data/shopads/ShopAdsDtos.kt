package com.testlogon.android.data.shopads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.ads.CtaActionDto

/**
 * ADV x ECOM (B2) — wire DTOs for POST /ui/ads/shop/serve (op shop_serve_endpoint, _ShopServeIn).
 *
 * surface is shop_search|shop_browse; query/category_id are the optional shop context; limit 1..10.
 * The response is a STANDALONE product-linked sponsored unit list: each unit carries the product_id +
 * a buy_product CTA (reuse E2) + the impression/click tracking ids so the app fires impression on
 * render + click on tap via the EXISTING /ui/ads/track money-path (funds-guarded, idempotent,
 * standalone -> platform 100%). Sponsored products are NOT tippable (tippable=false).
 */
@JsonClass(generateAdapter = true)
data class ShopServeInDto(
    @Json(name = "surface") val surface: String,
    @Json(name = "query") val query: String = "",
    @Json(name = "category_id") val categoryId: String = "",
    @Json(name = "limit") val limit: Int = 3,
)

@JsonClass(generateAdapter = true)
data class ShopServeOutDto(
    @Json(name = "sponsored") val sponsored: List<ShopSponsoredUnitDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/**
 * One served STANDALONE sponsored product unit. product_id + product_category_id resolve the catalog
 * product page; product_name/product_price_cents/product_image_url render the card (server enriches
 * from the live listing). creative_id/campaign_id/account_id/ad_click_id round-trip to /ui/ads/track.
 * All fields defaulted so a partial / older-server unit parses cleanly.
 */
@JsonClass(generateAdapter = true)
data class ShopSponsoredUnitDto(
    @Json(name = "unit_id") val unitId: String = "",
    @Json(name = "sponsor_label") val sponsorLabel: String = "Sponsored",
    @Json(name = "headline") val headline: String? = null,
    @Json(name = "body") val body: String = "",
    @Json(name = "cta_text") val ctaText: String = "Shop now",
    @Json(name = "ctas") val ctas: List<CtaActionDto> = emptyList(),
    @Json(name = "product_id") val productId: String = "",
    @Json(name = "product_category_id") val productCategoryId: String = "",
    @Json(name = "product_name") val productName: String = "",
    @Json(name = "product_price_cents") val productPriceCents: Long = 0,
    @Json(name = "product_currency") val productCurrency: String = "USD",
    @Json(name = "product_image_url") val productImageUrl: String = "",
    @Json(name = "image_url") val imageUrl: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "ad_click_id") val adClickId: String = "",
    @Json(name = "content_owner_id") val contentOwnerId: String = "",
    @Json(name = "surface") val surface: String = "shop_browse",
    @Json(name = "tippable") val tippable: Boolean = false,
)

/**
 * ADV x ECOM (B4) — wire DTOs for POST /ui/ads/boost/product (op boost_product_endpoint,
 * _ProductBoostIn). Seller BOOST-this-product: from a catalog LISTING create/reuse the seller ad
 * account + a campaign + a product creative prefilled from the listing. OWNER-CHECKED server-side
 * (a non-owner gets 403). item_id (min 1) is required; budget/bid default sensibly.
 */
@JsonClass(generateAdapter = true)
data class ProductBoostInDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "category_id") val categoryId: String = "",
    @Json(name = "budget_cents") val budgetCents: Int = 5000,
    @Json(name = "bid_cpc_cents") val bidCpcCents: Int = 50,
    @Json(name = "bid_cpm_cents") val bidCpmCents: Int = 500,
    @Json(name = "bid_cpa_cents") val bidCpaCents: Int = 500,
    @Json(name = "duration_days") val durationDays: Int = 7,
    @Json(name = "objective") val objective: String = "traffic",
)

@JsonClass(generateAdapter = true)
data class ProductBoostOutDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "product_id") val productId: String = "",
    @Json(name = "product_name") val productName: String = "",
    @Json(name = "product_price_cents") val productPriceCents: Long = 0,
    @Json(name = "budget_cents") val budgetCents: Long = 0,
    @Json(name = "bid_cpc_cents") val bidCpcCents: Int = 0,
    @Json(name = "bid_cpm_cents") val bidCpmCents: Int = 0,
    @Json(name = "status") val status: String = "",
)
