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
    suspend fun cancelAll(): ApiResult<BulkCancelResult>
    suspend fun placeQuote(symbolId: Int, bidPrice: Long, askPrice: Long, bidQty: Long, askQty: Long): ApiResult<QuoteAck>
    suspend fun placeAlgo(algoType: String, symbolId: Int, side: OrderSide, qty: Long, stopPrice: Long?, limitPrice: Long?): ApiResult<AlgoAck>
    suspend fun placeOto(symbolId: Int, parentSide: OrderSide, parentPrice: Long, parentQty: Long, childSide: OrderSide, childPrice: Long, childQty: Long): ApiResult<OtoAck>
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

    override suspend fun cancelAll(): ApiResult<BulkCancelResult> =
        withContext(io) { apiCall { api.bulkCancel(emptyMap()).toDomain() } }

    override suspend fun placeQuote(symbolId: Int, bidPrice: Long, askPrice: Long, bidQty: Long, askQty: Long): ApiResult<QuoteAck> =
        withContext(io) { apiCall { api.placeQuote(QuoteDto(symbolId, bidPrice, askPrice, bidQty, askQty)).toDomain() } }

    override suspend fun placeAlgo(algoType: String, symbolId: Int, side: OrderSide, qty: Long, stopPrice: Long?, limitPrice: Long?): ApiResult<AlgoAck> =
        withContext(io) { apiCall { api.placeAlgo(AlgoOrderDto(algoType, symbolId, side.wire, qty, stopPrice, limitPrice)).toDomain() } }

    override suspend fun placeOto(symbolId: Int, parentSide: OrderSide, parentPrice: Long, parentQty: Long, childSide: OrderSide, childPrice: Long, childQty: Long): ApiResult<OtoAck> =
        withContext(io) { apiCall { api.placeOto(OtoOrderDto(symbolId, parentSide.wire, parentPrice, parentQty, childSide.wire, childPrice, childQty)).toDomain() } }

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
