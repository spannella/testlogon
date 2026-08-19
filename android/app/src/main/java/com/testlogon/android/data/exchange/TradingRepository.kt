package com.testlogon.android.data.exchange

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Trader order-entry data layer over [TradingApi]. Place / amend / cancel orders and read the margin
 * account, mapped to domain types and wrapped in [ApiResult]. All calls require `me_trade_enabled`.
 */
interface TradingRepository {
    suspend fun placeOrder(
        symbolId: Int,
        side: OrderSide,
        price: Long,
        qty: Long,
        clordid: String,
        market: Boolean? = null,
        tif: String? = null,
        postOnly: Boolean? = null,
        hidden: Boolean? = null,
        aon: Boolean? = null,
        displayQty: Long? = null,
        minQty: Long? = null,
        expiryNs: Long? = null,
    ): ApiResult<OrderAck>
    suspend fun amendOrder(clordid: String, newQty: Long, newPrice: Long? = null): ApiResult<OrderAck>
    suspend fun cancelOrder(clordid: String): ApiResult<CancelAck>
    suspend fun marginAccount(): ApiResult<MarginAccount>
    suspend fun execEvents(): ApiResult<ExecEvents>
    suspend fun pmState(symbolId: Int): ApiResult<PmState>
    // Pre-staged (behind TradingFeatures flags):
    suspend fun placeOco(symbolId: Int, aSide: OrderSide, aPrice: Long, aQty: Long, bSide: OrderSide, bPrice: Long, bQty: Long): ApiResult<OcoAck>
    suspend fun placeFunding(rateBps: Long, qty: Long, isBorrow: Boolean, durationSeconds: Long?, symbolId: Int?): ApiResult<FundingAck>
    suspend fun spotBalance(): ApiResult<SpotBalance>
    suspend fun spotDeposit(asset: Int, amount: Long): ApiResult<SpotDepositAck>
    suspend fun deposit(amount: Long): ApiResult<DepositAck>
    /** ADMIN: apply per-symbol margin/fee/borrow config. */
    suspend fun marginConfig(
        symbolId: Int,
        initialMarginBps: Long,
        maintenanceMarginBps: Long,
        liquidationFeeBps: Long,
        hourlyBorrowRateBps: Long,
        makerFeeBps: Long,
        takerFeeBps: Long,
        maxPositionQty: Long,
    ): ApiResult<MarginConfigAck>
    suspend fun cancelAll(): ApiResult<BulkCancelResult>
    suspend fun placeQuote(symbolId: Int, bidPrice: Long, askPrice: Long, bidQty: Long, askQty: Long): ApiResult<QuoteAck>
    suspend fun placeAlgo(algoType: String, symbolId: Int, side: OrderSide, qty: Long, stopPrice: Long?, limitPrice: Long?): ApiResult<AlgoAck>
    suspend fun placeOto(symbolId: Int, parentSide: OrderSide, parentPrice: Long, parentQty: Long, childSide: OrderSide, childPrice: Long, childQty: Long): ApiResult<OtoAck>
    /** Fees (custody-exchange-gaps): the caller's fee schedule + the enriched fills-fees feed. */
    suspend fun feeSchedule(symbolId: Int): ApiResult<FeeSchedule>
    suspend fun fillsFees(): ApiResult<FillsFees>
    /** Recent forced-liquidation events (404 -> empty feed). */
    suspend fun liquidations(): ApiResult<Liquidations>
    /** Recent perpetual funding payments (404 -> empty feed). */
    suspend fun fundingPayments(): ApiResult<FundingPayments>

    // ---- ADMIN engine-config (exchange-admin-config); 404 (undeployed) -> un-applied ack. ----
    suspend fun matchingAlgo(symbolId: Int, algo: Int, specialistMpid: String?, specialistPct: Int?): ApiResult<EngineConfigAck>
    suspend fun spreadConfig(spreadSymbolId: Int, leg1: Int, leg2: Int, leg1Ratio: Int?, leg2Ratio: Int?): ApiResult<EngineConfigAck>
    suspend fun tradingParams(symbolId: Int, maxQty: Int?, maxNotional: Long?, priceBandPct: Long?, circuitBreakerPct: Long?, minBlockSize: Int?): ApiResult<EngineConfigAck>
    suspend fun riskConfig(maxNotional: Long, windowSeconds: Int, mpid: String?): ApiResult<EngineConfigAck>
    suspend fun spotIndex(symbolId: Int, spotIndexPrice: Long): ApiResult<EngineConfigAck>
    suspend fun spotConfig(symbolId: Int, baseAsset: Int, quoteAsset: Int): ApiResult<EngineConfigAck>

    // ---- ADMIN prediction-markets (exchange-admin-config); 404 (undeployed) -> un-applied ack / empty log. ----
    suspend fun pmConfig(symbolId: Int, faceValue: Long, resolver: String?): ApiResult<PmConfigAck>
    suspend fun pmGroupConfig(groupId: Int, outcomes: List<Int>, faceValue: Long, resolver: String?): ApiResult<PmConfigAck>
    suspend fun pmResolve(symbolId: Int, outcome: String, source: String?): ApiResult<PmConfigAck>
    suspend fun pmGroupResolve(groupId: Int, winningSymbolId: Int, source: String?): ApiResult<PmConfigAck>
    suspend fun pmResolutions(): ApiResult<List<PmResolution>>

    // ---- Trader staking + auctions (peer mechanisms); 404 (undeployed) -> un-applied ack. ----
    suspend fun stakeRequest(symbolId: Int?, minCollateral: Long, maxStakePct: Long, lockupSeconds: Int, durationSeconds: Int): ApiResult<StakeAuctionAck>
    suspend fun stakeOffer(requestId: Long, collateralAmount: Long, stakePct: Long): ApiResult<StakeAuctionAck>
    suspend fun auctionRequest(symbolId: Int?, qty: Int, reservePrice: Long?, durationSeconds: Int?): ApiResult<StakeAuctionAck>
    suspend fun auctionBid(auctionId: Long, price: Long, qty: Int): ApiResult<StakeAuctionAck>
}

@Singleton
class TradingRepositoryImpl @Inject constructor(
    private val api: TradingApi,
    private val errorParser: ApiErrorParser,
) : TradingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun placeOrder(
        symbolId: Int,
        side: OrderSide,
        price: Long,
        qty: Long,
        clordid: String,
        market: Boolean?,
        tif: String?,
        postOnly: Boolean?,
        hidden: Boolean?,
        aon: Boolean?,
        displayQty: Long?,
        minQty: Long?,
        expiryNs: Long?,
    ): ApiResult<OrderAck> = withContext(io) {
        apiCall {
            api.placeOrder(
                PlaceOrderDto(symbolId, side.wire, price, qty, clordid, market, tif, postOnly, hidden, aon, displayQty, minQty, expiryNs),
            ).toOrderAck(clordid)
        }
    }

    override suspend fun amendOrder(clordid: String, newQty: Long, newPrice: Long?): ApiResult<OrderAck> =
        withContext(io) {
            apiCall { api.amendOrder(clordid, AmendOrderDto(newQty, newPrice)).toOrderAck(clordid) }
        }

    override suspend fun cancelOrder(clordid: String): ApiResult<CancelAck> =
        withContext(io) { apiCall { api.cancelOrder(clordid).toCancelAck(clordid) } }

    override suspend fun marginAccount(): ApiResult<MarginAccount> =
        withContext(io) { apiCall { api.getMarginAccount().toDomain() } }

    override suspend fun execEvents(): ApiResult<ExecEvents> =
        withContext(io) { apiCall { api.algoEvents().toDomain() } }

    override suspend fun pmState(symbolId: Int): ApiResult<PmState> =
        withContext(io) { apiCall { api.getPmState(symbolId).toDomain() } }

    override suspend fun placeOco(symbolId: Int, aSide: OrderSide, aPrice: Long, aQty: Long, bSide: OrderSide, bPrice: Long, bQty: Long): ApiResult<OcoAck> =
        withContext(io) {
            apiCall {
                api.placeOco(
                    OcoOrderDto(symbolId, listOf(OcoLegDto(aSide.wire, aPrice, aQty), OcoLegDto(bSide.wire, bPrice, bQty))),
                ).toDomain()
            }
        }

    override suspend fun placeFunding(rateBps: Long, qty: Long, isBorrow: Boolean, durationSeconds: Long?, symbolId: Int?): ApiResult<FundingAck> =
        withContext(io) { apiCall { api.placeFunding(FundingOrderDto(rateBps, qty, isBorrow, durationSeconds, symbolId, null)).toDomain() } }

    override suspend fun spotBalance(): ApiResult<SpotBalance> =
        withContext(io) { apiCall { api.spotBalance().toDomain() } }

    override suspend fun spotDeposit(asset: Int, amount: Long): ApiResult<SpotDepositAck> =
        withContext(io) { apiCall { api.spotDeposit(SpotDepositDto(asset, amount)).toDomain() } }

    override suspend fun deposit(amount: Long): ApiResult<DepositAck> =
        withContext(io) { apiCall { api.marginDeposit(MarginDepositDto(amount)).toDomain() } }

    override suspend fun marginConfig(
        symbolId: Int,
        initialMarginBps: Long,
        maintenanceMarginBps: Long,
        liquidationFeeBps: Long,
        hourlyBorrowRateBps: Long,
        makerFeeBps: Long,
        takerFeeBps: Long,
        maxPositionQty: Long,
    ): ApiResult<MarginConfigAck> = withContext(io) {
        apiCall {
            api.marginConfig(
                MarginConfigDto(
                    symbolId = symbolId,
                    initialMarginBps = initialMarginBps,
                    maintenanceMarginBps = maintenanceMarginBps,
                    liquidationFeeBps = liquidationFeeBps,
                    hourlyBorrowRateBps = hourlyBorrowRateBps,
                    makerFeeBps = makerFeeBps,
                    takerFeeBps = takerFeeBps,
                    maxPositionQty = maxPositionQty,
                ),
            ).toDomain()
        }
    }

    override suspend fun cancelAll(): ApiResult<BulkCancelResult> =
        withContext(io) { apiCall { api.bulkCancel(emptyMap()).toDomain() } }

    override suspend fun placeQuote(symbolId: Int, bidPrice: Long, askPrice: Long, bidQty: Long, askQty: Long): ApiResult<QuoteAck> =
        withContext(io) { apiCall { api.placeQuote(QuoteDto(symbolId, bidPrice, askPrice, bidQty, askQty)).toDomain() } }

    override suspend fun placeAlgo(algoType: String, symbolId: Int, side: OrderSide, qty: Long, stopPrice: Long?, limitPrice: Long?): ApiResult<AlgoAck> =
        withContext(io) { apiCall { api.placeAlgo(AlgoOrderDto(algoType, symbolId, side.wire, qty, stopPrice, limitPrice)).toDomain() } }

    override suspend fun placeOto(symbolId: Int, parentSide: OrderSide, parentPrice: Long, parentQty: Long, childSide: OrderSide, childPrice: Long, childQty: Long): ApiResult<OtoAck> =
        withContext(io) { apiCall { api.placeOto(OtoOrderDto(symbolId, parentSide.wire, parentPrice, parentQty, childSide.wire, childPrice, childQty)).toDomain() } }

    override suspend fun feeSchedule(symbolId: Int): ApiResult<FeeSchedule> =
        withContext(io) { apiCall { api.getFeeSchedule(symbolId).toDomain() } }

    override suspend fun fillsFees(): ApiResult<FillsFees> =
        withContext(io) { emptyOn404(FillsFees(emptyList(), 0)) { api.getFillsFees().toDomain() } }

    override suspend fun liquidations(): ApiResult<Liquidations> =
        withContext(io) { emptyOn404(Liquidations(emptyList(), 0)) { api.getLiquidations().toDomain() } }

    override suspend fun fundingPayments(): ApiResult<FundingPayments> =
        withContext(io) { emptyOn404(FundingPayments(emptyList(), 0)) { api.getFundingPayments().toDomain() } }

    // ---- ADMIN engine-config. Not deployed to prod -> a 404 folds to an un-applied ack. ----

    private val notDeployedAck = EngineConfigAck(applied = false, symbolId = null, result = null, message = "Engine config endpoint not deployed")

    override suspend fun matchingAlgo(symbolId: Int, algo: Int, specialistMpid: String?, specialistPct: Int?): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.matchingAlgo(MatchingAlgoDto(symbolId, algo, specialistMpid, specialistPct)).toDomain() } }

    override suspend fun spreadConfig(spreadSymbolId: Int, leg1: Int, leg2: Int, leg1Ratio: Int?, leg2Ratio: Int?): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.spreadConfig(SpreadConfigDto(spreadSymbolId, leg1, leg2, leg1Ratio, leg2Ratio)).toDomain() } }

    override suspend fun tradingParams(symbolId: Int, maxQty: Int?, maxNotional: Long?, priceBandPct: Long?, circuitBreakerPct: Long?, minBlockSize: Int?): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.tradingParams(TradingParamsDto(symbolId, maxQty, maxNotional, priceBandPct, circuitBreakerPct, minBlockSize)).toDomain() } }

    override suspend fun riskConfig(maxNotional: Long, windowSeconds: Int, mpid: String?): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.riskConfig(RiskConfigDto(maxNotional, windowSeconds, mpid)).toDomain() } }

    override suspend fun spotIndex(symbolId: Int, spotIndexPrice: Long): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.spotIndex(SpotIndexDto(symbolId, spotIndexPrice)).toDomain() } }

    override suspend fun spotConfig(symbolId: Int, baseAsset: Int, quoteAsset: Int): ApiResult<EngineConfigAck> =
        withContext(io) { emptyOn404(notDeployedAck) { api.spotConfig(SpotConfigDto(symbolId, baseAsset, quoteAsset)).toDomain() } }

    // ---- ADMIN prediction-markets. Not deployed to prod -> a 404 folds to an un-applied ack / empty log. ----

    private val notDeployedPmAck = PmConfigAck(applied = false, symbolId = null, groupId = null, result = null, message = "PM admin endpoint not deployed")

    override suspend fun pmConfig(symbolId: Int, faceValue: Long, resolver: String?): ApiResult<PmConfigAck> =
        withContext(io) { emptyOn404(notDeployedPmAck) { api.pmConfig(PmConfigDto(symbolId, faceValue, resolver)).toDomain() } }

    override suspend fun pmGroupConfig(groupId: Int, outcomes: List<Int>, faceValue: Long, resolver: String?): ApiResult<PmConfigAck> =
        withContext(io) { emptyOn404(notDeployedPmAck) { api.pmGroupConfig(PmGroupConfigDto(groupId, outcomes, faceValue, resolver)).toDomain() } }

    override suspend fun pmResolve(symbolId: Int, outcome: String, source: String?): ApiResult<PmConfigAck> =
        withContext(io) { emptyOn404(notDeployedPmAck) { api.pmResolve(PmResolveDto(symbolId, outcome, source)).toDomain() } }

    override suspend fun pmGroupResolve(groupId: Int, winningSymbolId: Int, source: String?): ApiResult<PmConfigAck> =
        withContext(io) { emptyOn404(notDeployedPmAck) { api.pmGroupResolve(PmGroupResolveDto(groupId, winningSymbolId, source)).toDomain() } }

    override suspend fun pmResolutions(): ApiResult<List<PmResolution>> =
        withContext(io) { emptyOn404(emptyList<PmResolution>()) { api.getPmResolutions().map { it.toDomain() } } }

    // ---- Trader staking + auctions. Not deployed to prod -> a 404 folds to an un-applied ack. ----

    private fun notDeployedStakeAck(kind: StakeAuctionKind) =
        StakeAuctionAck(accepted = false, kind = kind, createdId = null, message = "Staking/auctions endpoint not deployed")

    override suspend fun stakeRequest(symbolId: Int?, minCollateral: Long, maxStakePct: Long, lockupSeconds: Int, durationSeconds: Int): ApiResult<StakeAuctionAck> =
        withContext(io) {
            emptyOn404(notDeployedStakeAck(StakeAuctionKind.STAKE_REQUEST)) {
                api.stakeRequest(StakeRequestDto(symbolId, minCollateral, maxStakePct, lockupSeconds, durationSeconds)).toDomain(StakeAuctionKind.STAKE_REQUEST)
            }
        }

    override suspend fun stakeOffer(requestId: Long, collateralAmount: Long, stakePct: Long): ApiResult<StakeAuctionAck> =
        withContext(io) {
            emptyOn404(notDeployedStakeAck(StakeAuctionKind.STAKE_OFFER)) {
                api.stakeOffer(StakeOfferDto(requestId, collateralAmount, stakePct)).toDomain(StakeAuctionKind.STAKE_OFFER)
            }
        }

    override suspend fun auctionRequest(symbolId: Int?, qty: Int, reservePrice: Long?, durationSeconds: Int?): ApiResult<StakeAuctionAck> =
        withContext(io) {
            emptyOn404(notDeployedStakeAck(StakeAuctionKind.AUCTION_REQUEST)) {
                api.auctionRequest(AuctionRequestDto(symbolId, qty, reservePrice, durationSeconds)).toDomain(StakeAuctionKind.AUCTION_REQUEST)
            }
        }

    override suspend fun auctionBid(auctionId: Long, price: Long, qty: Int): ApiResult<StakeAuctionAck> =
        withContext(io) {
            emptyOn404(notDeployedStakeAck(StakeAuctionKind.AUCTION_BID)) {
                api.auctionBid(AuctionBidDto(auctionId, price, qty)).toDomain(StakeAuctionKind.AUCTION_BID)
            }
        }

    /**
     * Like [apiCall] but a 404 (endpoint not deployed yet) folds to a Success carrying [emptyValue],
     * so the new liquidations/funding/fills-fees surfaces render their empty state instead of an error.
     */
    private suspend fun <T> emptyOn404(emptyValue: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == 404) ApiResult.Success(emptyValue) else ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
