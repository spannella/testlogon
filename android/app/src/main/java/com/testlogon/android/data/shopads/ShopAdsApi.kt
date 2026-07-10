package com.testlogon.android.data.shopads

import retrofit2.http.Body
import retrofit2.http.POST

/**
 * ADV x ECOM (B2/B4) — Retrofit client for the shop sponsored-products + seller boost endpoints.
 *
 * Paths are relative to the shared Retrofit base URL; the core-network interceptor chain attaches the
 * UI session cookie / Bearer / CSRF (both routes are behind require_ui_session). Suspend, typed body;
 * non-2xx surfaces as retrofit2.HttpException.
 *
 * Verified against app/routers/ads.py:
 *  - POST ui/ads/shop/serve    (_ShopServeIn)   -> {sponsored:[...], count} (B2)
 *  - POST ui/ads/boost/product (_ProductBoostIn) -> boost result (B4, 201, owner-checked)
 */
interface ShopAdsApi {

    @POST("ui/ads/shop/serve")
    suspend fun serveShop(@Body body: ShopServeInDto): ShopServeOutDto

    @POST("ui/ads/boost/product")
    suspend fun boostProduct(@Body body: ProductBoostInDto): ProductBoostOutDto
}
