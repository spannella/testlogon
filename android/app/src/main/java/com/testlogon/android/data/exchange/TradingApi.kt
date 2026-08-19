package com.testlogon.android.data.exchange

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

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

    /** ADMIN: set per-symbol margin/fee/borrow parameters. result == 0 means applied. */
    @POST("me/margin_config")
    suspend fun marginConfig(@Body body: MarginConfigDto): MarginConfigAckDto

    /** Deposit collateral into the margin account (credits balance/available; enables margin mode). */
    @POST("me/margin_deposit")
    suspend fun marginDeposit(@Body body: MarginDepositDto): MarginDepositAckDto

    /** Cancel ALL resting orders for this account (empty body). Clears quote/OTO legs too. */
    @POST("me/bulk_cancel")
    suspend fun bulkCancel(@Body body: Map<String, String>): BulkCancelAckDto

    /** Two-sided maker quote: rests a bid and an ask at once. */
    @POST("me/quote")
    suspend fun placeQuote(@Body body: QuoteDto): QuoteAckDto

    /** Conditional (algo) order: stop / stop_limit / stop_market / take_profit. */
    @POST("me/algo")
    suspend fun placeAlgo(@Body body: AlgoOrderDto): AlgoAckDto

    /** One-triggers-other: a parent order whose fill arms a child order. */
    @POST("me/oto")
    suspend fun placeOto(@Body body: OtoOrderDto): OtoAckDto

    /** Drain this session's async exec events (algo/oto triggers + fills that landed after placement). */
    @GET("me/algo/events")
    suspend fun algoEvents(): ExecEventsDto

    /** Binary prediction-market state for a symbol (404 when the symbol is not a configured PM). */
    @GET("me/pm_state")
    suspend fun getPmState(@Query("symbolid") symbolId: Int): PmStateDto

    // ---- Pre-staged (behind TradingFeatures flags); align field names with the backend port. ----

    /** One-cancels-other: two opposite-side legs; a fill on one cancels the other. */
    @POST("me/oco")
    suspend fun placeOco(@Body body: OcoOrderDto): OcoAckDto

    /** On-book funding/lending: submit a borrow or lend order into the funding market. */
    @POST("me/funding_order")
    suspend fun placeFunding(@Body body: FundingOrderDto): FundingAckDto

    /** Read spot (cash) balances per asset. */
    @GET("me/spot_balance")
    suspend fun spotBalance(): SpotBalanceDto

    /** Credit a spot asset balance. */
    @POST("me/spot_deposit")
    suspend fun spotDeposit(@Body body: SpotDepositDto): SpotDepositAckDto
}
