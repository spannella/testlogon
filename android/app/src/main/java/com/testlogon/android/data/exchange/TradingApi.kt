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

    /**
     * Reference USD prices for cross-venue valuation (indicative). STUB today:
     * {prices:{SYMBOL:"usd-string"}, quote:"USD", source, stub, note}. 404 until deployed -> the
     * repository degrades to an unavailable [PriceMap] (callers keep the source-native sum).
     */
    @GET("me/prices")
    suspend fun getPrices(): PricesDto

    /** Read spot (cash) balances per asset. */
    @GET("me/spot_balance")
    suspend fun spotBalance(): SpotBalanceDto

    /** Credit a spot asset balance. */
    @POST("me/spot_deposit")
    suspend fun spotDeposit(@Body body: SpotDepositDto): SpotDepositAckDto
    // ==== Fees (custody-exchange-gaps) ====

    /**
     * The maker/taker/liquidation fee schedule for a symbol. source is "engine" (a configured
     * per-symbol/venue rate) or "venue_default"; configured tells whether this symbol has an override.
     */
    @GET("me/fees/schedule")
    suspend fun getFeeSchedule(@Query("symbolid") symbolId: Int): FeeScheduleDto

    /**
     * Recent fills enriched with the REAL per-fill fee + maker/taker liquidity from the engine feed
     * (custody-exchange-gaps). 404 until deployed -> the repository degrades to an empty feed.
     */
    @GET("me/fills/fees")
    suspend fun getFillsFees(): FillsFeesDto

    /**
     * OPTIONAL authoritative maker/taker fee-tier read (30d volume + tier + rates + next tier). 404
     * until deployed -> the repository folds to null and the screen falls back to the client estimate.
     */
    @GET("me/fees/tier")
    suspend fun getFeeTier(): FeeTierDto

    /**
     * The account's LIVE working (resting) orders straight from the engine (order-management read).
     * Unlike the session-tracked list, this survives app restarts + reflects quote/OTO legs. Parsed
     * defensively ({orders:[{clordid,symbolid,side,price,qty,...}]}); 404/undeployed -> empty feed.
     */
    @GET("me/orders/live")
    suspend fun getOrdersLive(): LiveOrdersDto

    /** This account's recent forced-liquidation events (symbol, qty, mark, realized PnL, fee). 404 when undeployed. */
    @GET("me/liquidations")
    suspend fun getLiquidations(): LiquidationsDto

    /** This account's recent perpetual funding payments (signed: negative=paid, positive=received). 404 when undeployed. */
    @GET("me/funding/payments")
    suspend fun getFundingPayments(): FundingPaymentsDto

    // ==== Admin engine-config (exchange-admin-config); all admin-only, ack {status,...}; 404 -> degrade. ====

    /** ADMIN: set per-symbol matching algorithm (0 = price-time; 1+ = pro-rata/specialist). */
    @POST("me/matching_algo")
    suspend fun matchingAlgo(@Body body: MatchingAlgoDto): EngineConfigAckDto

    /** ADMIN: define a two-leg spread instrument. */
    @POST("me/spread_config")
    suspend fun spreadConfig(@Body body: SpreadConfigDto): EngineConfigAckDto

    /** ADMIN: per-symbol trading-parameter / risk-limit overrides. */
    @POST("me/trading_params")
    suspend fun tradingParams(@Body body: TradingParamsDto): EngineConfigAckDto

    /** ADMIN: aggregate notional cap over a rolling window. */
    @POST("me/risk_config")
    suspend fun riskConfig(@Body body: RiskConfigDto): EngineConfigAckDto

    /** ADMIN: publish a spot index (mark) price for a symbol. */
    @POST("me/spot_index")
    suspend fun spotIndex(@Body body: SpotIndexDto): EngineConfigAckDto

    /** ADMIN: bind a symbol to its base/quote asset ids (defines a spot pair). */
    @POST("me/spot_config")
    suspend fun spotConfig(@Body body: SpotConfigDto): EngineConfigAckDto

    // ==== Admin prediction-markets (exchange-admin-config); admin-gated; ack {status,...}. ====
    // Not deployed to prod -> the repository degrades on 404 (like the engine-config routes).

    /** ADMIN: configure a binary PM on a symbol (face_value>1, optional designated resolver). */
    @POST("me/pm_config")
    suspend fun pmConfig(@Body body: PmConfigDto): PmConfigAckDto

    /** ADMIN: configure a categorical (grouped) PM: a group of mutually-exclusive outcome symbols. */
    @POST("me/pm_group_config")
    suspend fun pmGroupConfig(@Body body: PmGroupConfigDto): PmConfigAckDto

    /** ADMIN (designated resolver): resolve a binary PM to yes/no. 403 if the caller is not the resolver. */
    @POST("me/pm_resolve")
    suspend fun pmResolve(@Body body: PmResolveDto): PmConfigAckDto

    /** ADMIN (designated resolver): resolve a categorical PM to its winning outcome symbol. */
    @POST("me/pm_group_resolve")
    suspend fun pmGroupResolve(@Body body: PmGroupResolveDto): PmConfigAckDto

    /** ADMIN: the resolution audit log (symbol/group, outcome, resolver, ts, source). 404 -> empty. */
    @GET("me/pm_resolutions")
    suspend fun getPmResolutions(): List<PmResolutionDto>

    // ==== Trader staking + auctions (peer mechanisms). Ack JSON carries the created id + status.
    // Not deployed to prod yet -> the repository degrades on 404 (like the engine-config routes).
    // There is NO list/GET for open stake requests or auctions -> action forms surface the returned id. ====

    /** Create a stake request (offer your position as collateral for others to stake against). */
    @POST("me/stake_request")
    suspend fun stakeRequest(@Body body: StakeRequestDto): StakeAuctionAckDto

    /** Offer collateral to stake against an open stake request (by request id). */
    @POST("me/stake_offer")
    suspend fun stakeOffer(@Body body: StakeOfferDto): StakeAuctionAckDto

    /** Create an auction to sell a position quantity (optional reserve price + duration). */
    @POST("me/auction_request")
    suspend fun auctionRequest(@Body body: AuctionRequestDto): StakeAuctionAckDto

    /** Place a bid on an open auction (by auction id). */
    @POST("me/auction_bid")
    suspend fun auctionBid(@Body body: AuctionBidDto): StakeAuctionAckDto
    // ==== Discovery browse (STUB; empty + stub:true + note). 404 -> repository degrades to empty. ====

    /** Browse open stake requests (STUB: empty list + note until the matching backend ships). */
    @GET("me/stake_requests")
    suspend fun getStakeRequests(): StakeRequestsBrowseDto

    /** Browse open auctions (STUB: empty list + note until the matching backend ships). */
    @GET("me/auctions")
    suspend fun getAuctions(): AuctionsBrowseDto
}
