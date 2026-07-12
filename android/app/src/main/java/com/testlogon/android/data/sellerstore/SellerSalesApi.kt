package com.testlogon.android.data.sellerstore

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ECOM-SELLER (G3) — Retrofit interface for the SELLER-SCOPED sales / fulfilment surface
 * (`/ui/seller/sales`). Unlike the admin-only `/ui/orders` control plane, these routes run under
 * `require_ui_session` for ANY authenticated seller and return ONLY the caller's own ship groups.
 * Session cookies + X-CSRF-Token are attached by the interceptor chain.
 *
 *  - GET  ui/seller/sales?limit=&cursor=              -> SellerSaleListOut (caller's ship groups)
 *  - GET  ui/seller/sales/{shipGroupId}               -> SellerSaleOut     (404 if not caller's)
 *  - POST ui/seller/sales/{shipGroupId}/transition    -> SellerSaleOut     (scoped fulfilment)
 */
interface SellerSalesApi {

    @GET("ui/seller/sales")
    suspend fun listSales(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): SellerSaleListOutDto

    @GET("ui/seller/sales/{shipGroupId}")
    suspend fun sale(@Path("shipGroupId") shipGroupId: String): SellerSaleDto

    @POST("ui/seller/sales/{shipGroupId}/transition")
    suspend fun transition(
        @Path("shipGroupId") shipGroupId: String,
        @Body body: SellerSaleTransitionRequestDto,
    ): SellerSaleDto
}
