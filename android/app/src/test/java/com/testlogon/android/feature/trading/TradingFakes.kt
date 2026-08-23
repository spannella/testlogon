package com.testlogon.android.feature.trading

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutAck
import com.testlogon.android.data.bailout.BailoutAuction
import com.testlogon.android.data.bailout.BailoutPrefs
import com.testlogon.android.data.bailout.BailoutRepository
import com.testlogon.android.data.bailout.DistressPosition
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.CustodyReader
import com.testlogon.android.data.custody.StakingDashboard
import com.testlogon.android.data.exchange.AuctionsBrowse
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FeeSchedule
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.HistoryBars
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.LiveOrders
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PmResolution
import com.testlogon.android.data.exchange.PmState
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.SpotBalance
import com.testlogon.android.data.exchange.StakeRequestsBrowse
import com.testlogon.android.data.exchange.Trade
import com.testlogon.android.data.exchange.TradingRepository

/**
 * Shared JVM test doubles for the trading-surface ViewModel tests. Reads default to honest empty
 * Successes (mirroring the degrade-on-404 folding the real repos do); the fields are `var` so a happy
 * path can override just what it needs. Mutations are unused by the read-only VMs under test and throw.
 */

/** Narrow custody read fake — the seam that unblocks Portfolio/Invest testing. */
class FakeCustodyReader(
    var balanceResult: ApiResult<CustodyBalances> = ApiResult.Success(CustodyBalances(vault = "", tier = "-", rows = emptyList())),
    var stakingResult: ApiResult<StakingDashboard> = ApiResult.Success(StakingDashboard.unavailable()),
) : CustodyReader {
    override suspend fun getBalance(): ApiResult<CustodyBalances> = balanceResult
    override suspend fun getStaking(): ApiResult<StakingDashboard> = stakingResult
}

private fun unused(): Nothing = throw UnsupportedOperationException("not used by the VM under test")

/** ExchangeRepository fake: symbols/orderBook/trades/candles/history overridable; empty by default. */
open class FakeExchangeRepository(
    var symbolsResult: ApiResult<List<Instrument>> = ApiResult.Success(emptyList()),
) : ExchangeRepository {
    var orderBookResult: (Int) -> ApiResult<OrderBook> = { ApiResult.Success(OrderBook(it, emptyList(), emptyList(), null, null)) }
    var tradesResult: (Int) -> ApiResult<List<Trade>> = { ApiResult.Success(emptyList()) }
    var candlesResult: (Int) -> ApiResult<List<Candle>> = { ApiResult.Success(emptyList()) }
    var historyResult: (Int) -> ApiResult<HistoryBars> = { ApiResult.Success(HistoryBars(it, "1d", emptyList())) }

    override suspend fun symbols(): ApiResult<List<Instrument>> = symbolsResult
    override suspend fun orderBook(symbolId: Int, depth: Int): ApiResult<OrderBook> = orderBookResult(symbolId)
    override suspend fun candles(symbolId: Int, intervalSec: Int): ApiResult<List<Candle>> = candlesResult(symbolId)
    override suspend fun trades(symbolId: Int): ApiResult<List<Trade>> = tradesResult(symbolId)
    override suspend fun getHistory(symbolId: Int, interval: String, from: Long?, to: Long?, cursor: String?): ApiResult<HistoryBars> =
        historyResult(symbolId)
}

/** TradingRepository fake: only the read methods the VMs use are meaningfully overridable. */
open class FakeTradingRepository : TradingRepository {
    var spotBalanceResult: ApiResult<SpotBalance> = ApiResult.Success(SpotBalance(emptyList(), ""))
    var marginAccountResult: ApiResult<MarginAccount> = ApiResult.Success(MarginAccount(0, 0, 0, 0, null, 0, false, ""))
    var pricesResult: ApiResult<PriceMap> = ApiResult.Success(PriceMap.unavailable())
    var fillsFeesResult: ApiResult<FillsFees> = ApiResult.Success(FillsFees(emptyList(), 0))
    var fundingPaymentsResult: ApiResult<FundingPayments> = ApiResult.Success(FundingPayments(emptyList(), 0))
    var liquidationsResult: ApiResult<Liquidations> = ApiResult.Success(Liquidations(emptyList(), 0))
    var pmResolutionsResult: ApiResult<List<PmResolution>> = ApiResult.Success(emptyList())
    var stakeRequestsBrowseResult: ApiResult<StakeRequestsBrowse> = ApiResult.Success(StakeRequestsBrowse.unavailable())
    var auctionsBrowseResult: ApiResult<AuctionsBrowse> = ApiResult.Success(AuctionsBrowse.unavailable())

    override suspend fun spotBalance(): ApiResult<SpotBalance> = spotBalanceResult
    override suspend fun marginAccount(): ApiResult<MarginAccount> = marginAccountResult
    override suspend fun getPrices(): ApiResult<PriceMap> = pricesResult
    override suspend fun fillsFees(): ApiResult<FillsFees> = fillsFeesResult
    override suspend fun fundingPayments(): ApiResult<FundingPayments> = fundingPaymentsResult
    override suspend fun liquidations(): ApiResult<Liquidations> = liquidationsResult
    override suspend fun pmResolutions(): ApiResult<List<PmResolution>> = pmResolutionsResult
    override suspend fun stakeRequestsBrowse(): ApiResult<StakeRequestsBrowse> = stakeRequestsBrowseResult
    override suspend fun auctionsBrowse(): ApiResult<AuctionsBrowse> = auctionsBrowseResult

    // ---- unused mutations / config / other reads ----
    override suspend fun placeOrder(symbolId: Int, side: OrderSide, price: Long, qty: Long, clordid: String, market: Boolean?, tif: String?, postOnly: Boolean?, hidden: Boolean?, aon: Boolean?, displayQty: Long?, minQty: Long?, expiryNs: Long?) = unused()
    override suspend fun amendOrder(clordid: String, newQty: Long, newPrice: Long?) = unused()
    override suspend fun cancelOrder(clordid: String) = unused()
    override suspend fun execEvents() = unused()
    override suspend fun pmState(symbolId: Int): ApiResult<PmState> = unused()
    override suspend fun placeOco(symbolId: Int, aSide: OrderSide, aPrice: Long, aQty: Long, bSide: OrderSide, bPrice: Long, bQty: Long) = unused()
    override suspend fun placeFunding(rateBps: Long, qty: Long, isBorrow: Boolean, durationSeconds: Long?, symbolId: Int?) = unused()
    override suspend fun spotDeposit(asset: Int, amount: Long) = unused()
    override suspend fun deposit(amount: Long) = unused()
    override suspend fun marginConfig(symbolId: Int, initialMarginBps: Long, maintenanceMarginBps: Long, liquidationFeeBps: Long, hourlyBorrowRateBps: Long, makerFeeBps: Long, takerFeeBps: Long, maxPositionQty: Long) = unused()
    override suspend fun cancelAll() = unused()
    override suspend fun placeQuote(symbolId: Int, bidPrice: Long, askPrice: Long, bidQty: Long, askQty: Long) = unused()
    override suspend fun placeAlgo(algoType: String, symbolId: Int, side: OrderSide, qty: Long, stopPrice: Long?, limitPrice: Long?) = unused()
    override suspend fun placeOto(symbolId: Int, parentSide: OrderSide, parentPrice: Long, parentQty: Long, childSide: OrderSide, childPrice: Long, childQty: Long) = unused()
    override suspend fun feeSchedule(symbolId: Int): ApiResult<FeeSchedule> = unused()
    override suspend fun ordersLive(): ApiResult<LiveOrders> = unused()
    override suspend fun matchingAlgo(symbolId: Int, algo: Int, specialistMpid: String?, specialistPct: Int?) = unused()
    override suspend fun spreadConfig(spreadSymbolId: Int, leg1: Int, leg2: Int, leg1Ratio: Int?, leg2Ratio: Int?) = unused()
    override suspend fun tradingParams(symbolId: Int, maxQty: Int?, maxNotional: Long?, priceBandPct: Long?, circuitBreakerPct: Long?, minBlockSize: Int?) = unused()
    override suspend fun riskConfig(maxNotional: Long, windowSeconds: Int, mpid: String?) = unused()
    override suspend fun spotIndex(symbolId: Int, spotIndexPrice: Long) = unused()
    override suspend fun spotConfig(symbolId: Int, baseAsset: Int, quoteAsset: Int) = unused()
    override suspend fun pmConfig(symbolId: Int, faceValue: Long, resolver: String?) = unused()
    override suspend fun pmGroupConfig(groupId: Int, outcomes: List<Int>, faceValue: Long, resolver: String?) = unused()
    override suspend fun pmResolve(symbolId: Int, outcome: String, source: String?) = unused()
    override suspend fun pmGroupResolve(groupId: Int, winningSymbolId: Int, source: String?) = unused()
    override suspend fun stakeRequest(symbolId: Int?, minCollateral: Long, maxStakePct: Long, lockupSeconds: Int, durationSeconds: Int) = unused()
    override suspend fun stakeOffer(requestId: Long, collateralAmount: Long, stakePct: Long) = unused()
    override suspend fun auctionRequest(symbolId: Int?, qty: Int, reservePrice: Long?, durationSeconds: Int?) = unused()
    override suspend fun auctionBid(auctionId: Long, price: Long, qty: Int) = unused()
}

/** BailoutRepository fake: bailouts() overridable; everything else degrade-empty / unused. */
open class FakeBailoutRepository(
    var bailoutsResult: ApiResult<List<BailoutAuction>> = ApiResult.Success(emptyList()),
) : BailoutRepository {
    override suspend fun distress(): ApiResult<List<DistressPosition>> = ApiResult.Success(emptyList())
    override suspend fun bailouts(): ApiResult<List<BailoutAuction>> = bailoutsResult
    override suspend fun positionBailout(symbolId: Int): ApiResult<BailoutAuction?> = ApiResult.Success(null)
    override suspend fun prefs(): ApiResult<BailoutPrefs> = unused()
    override suspend fun openBailout(symbolId: Int, maxShareBps: Int, closeTs: Long?): ApiResult<BailoutAuction> = unused()
    override suspend fun placeBid(auctionId: String, capitalCents: Long, shareBps: Int): ApiResult<BailoutAck> = unused()
    override suspend fun clear(auctionId: String): ApiResult<BailoutAuction> = unused()
    override suspend fun putPrefs(autoEnabled: Boolean, defaultMaxShareBps: Int): ApiResult<BailoutPrefs> = unused()
}
