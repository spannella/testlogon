package com.testlogon.android.data.exchange

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the trader order-entry (`me/ (matching-engine)`) endpoints. Write-only order
 * lifecycle (place / amend / cancel) plus the single account-state read. Auth rides on the shared
 * cookie session; all calls require `me_trade_enabled` on the account (else the engine 403s).
 *
 * There is NO server-side list of working orders or fills history (those paths are 405/404), so the
 * client tracks its own open orders + session fills from these acks — see the trading store.
 */
interface TradingApi {

    /** Place a new order. `nak` comes back as HTTP 200 with status="nak" (see [OrderAckDto.status]). */
    @POST("me/orders")
    suspend fun placeOrder(@Body body: PlaceOrderDto): OrderAckDto

    /** Amend a resting order in place (reduce qty keeps queue priority). Body uses `new_qty`/`new_price`. */
    @PATCH("me/orders/{clordid}")
    suspend fun amendOrder(@Path("clordid") clordid: String, @Body body: AmendOrderDto): OrderAckDto

    /** Cancel a resting order by its client order id. */
    @DELETE("me/orders/{clordid}")
    suspend fun cancelOrder(@Path("clordid") clordid: String): OrderAckDto

    /** Margin account snapshot: cash balance, reserved margin, and the (single net) position. */
    @GET("me/margin_account")
    suspend fun getMarginAccount(): MarginAccountDto
}
