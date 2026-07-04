package com.testlogon.android.data.sellerstore

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ECOM (seller store) — Retrofit interface for the order-lifecycle control plane (`/ui/orders`). The
 * list requires a scope (status or user_id). Fulfilment is driven by POSTing a `target_status` from the
 * order's `allowed_transitions`; cancel is a dedicated action. Session cookies + X-CSRF-Token are
 * attached by the interceptor chain.
 *
 *  - GET  ui/orders?status=&limit=&cursor=            -> OrderListOut
 *  - GET  ui/orders/{order_id}/lifecycle              -> OrderLifecycleOut
 *  - POST ui/orders/{order_id}/transition             -> OrderTransitionResult (body OrderTransitionRequest)
 *  - POST ui/orders/{order_id}/cancel                 -> OrderLifecycleOut     (body OrderCancelIn)
 */
interface SellerOrdersApi {

    @GET("ui/orders")
    suspend fun listOrders(
        @Query("status") status: String? = null,
        @Query("user_id") userId: String? = null,
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): OrderListOutDto

    @GET("ui/orders/{orderId}/lifecycle")
    suspend fun lifecycle(@Path("orderId") orderId: String): OrderLifecycleDto

    @POST("ui/orders/{orderId}/transition")
    suspend fun transition(
        @Path("orderId") orderId: String,
        @Body body: OrderTransitionRequestDto,
    ): OrderTransitionResultDto

    @POST("ui/orders/{orderId}/cancel")
    suspend fun cancel(
        @Path("orderId") orderId: String,
        @Body body: OrderCancelDto,
    ): OrderLifecycleDto
}
