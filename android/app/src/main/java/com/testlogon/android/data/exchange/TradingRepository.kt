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
    suspend fun placeOrder(symbolId: Int, side: OrderSide, price: Long, qty: Long, clordid: String): ApiResult<OrderAck>
    suspend fun amendOrder(clordid: String, newQty: Long, newPrice: Long? = null): ApiResult<OrderAck>
    suspend fun cancelOrder(clordid: String): ApiResult<CancelAck>
    suspend fun marginAccount(): ApiResult<MarginAccount>
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
    ): ApiResult<OrderAck> = withContext(io) {
        apiCall {
            api.placeOrder(PlaceOrderDto(symbolId, side.wire, price, qty, clordid)).toOrderAck(clordid)
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
