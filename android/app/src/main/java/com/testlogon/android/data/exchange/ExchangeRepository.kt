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
 * Markets (VIEW-ONLY) data layer over [ExchangeApi]. Fetches the `md/ (market-data)` market-data endpoints, maps
 * them to domain types, and returns them wrapped in [ApiResult].
 *
 * [symbols] falls back to a hardcoded catalogue if the (new) endpoint fails or returns empty, so the
 * Markets list is always populated with the three known instruments.
 */
interface ExchangeRepository {
    suspend fun symbols(): ApiResult<List<Instrument>>
    suspend fun orderBook(symbolId: Int, depth: Int = 20): ApiResult<OrderBook>
    suspend fun candles(symbolId: Int, intervalSec: Int = 60): ApiResult<List<Candle>>
    suspend fun trades(symbolId: Int): ApiResult<List<Trade>>

    /**
     * Long-range historical bars for the Analysis workbench. Calls the NEW `md/history` endpoint; on
     * 404/absence it DEGRADES to the recent-window [candles] read and returns a [HistoryBars] with
     * `stub = true` so the caller can show the "recent window only" banner. [interval] is the label
     * ("1m","5m","15m","1h","1d"); [from]/[to] are optional epoch-second bounds; [cursor] paginates.
     */
    suspend fun getHistory(
        symbolId: Int,
        interval: String,
        from: Long? = null,
        to: Long? = null,
        cursor: String? = null,
    ): ApiResult<HistoryBars>
}

@Singleton
class ExchangeRepositoryImpl @Inject constructor(
    private val api: ExchangeApi,
    private val errorParser: ApiErrorParser,
) : ExchangeRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun symbols(): ApiResult<List<Instrument>> = withContext(io) {
        when (val result = apiCall { api.getSymbols().symbols.map { it.toDomain() } }) {
            is ApiResult.Success ->
                if (result.data.isEmpty()) ApiResult.Success(FALLBACK_SYMBOLS) else result
            // The endpoint is new; degrade gracefully to the known instrument catalogue.
            is ApiResult.Failure -> ApiResult.Success(FALLBACK_SYMBOLS)
            is ApiResult.NetworkError -> ApiResult.Success(FALLBACK_SYMBOLS)
        }
    }

    override suspend fun orderBook(symbolId: Int, depth: Int): ApiResult<OrderBook> =
        withContext(io) { apiCall { api.getOrderBook(symbolId, depth).toDomain() } }

    override suspend fun candles(symbolId: Int, intervalSec: Int): ApiResult<List<Candle>> =
        withContext(io) { apiCall { api.getCandles(symbolId, intervalSec).bars.map { it.toDomain() } } }

    override suspend fun trades(symbolId: Int): ApiResult<List<Trade>> =
        withContext(io) { apiCall { api.getTrades(symbolId).trades.map { it.toDomain() } } }

    override suspend fun getHistory(
        symbolId: Int,
        interval: String,
        from: Long?,
        to: Long?,
        cursor: String?,
    ): ApiResult<HistoryBars> = withContext(io) {
        when (val result = apiCall { api.getHistory(symbolId, interval, from, to, cursor).toDomain(symbolId) }) {
            is ApiResult.Success -> result
            // The long-range endpoint does NOT exist yet: DEGRADE to the recent-window candles read
            // and flag the result as a stub so the workbench can show its "recent window only" banner.
            // A network error (offline) is NOT degraded — surface it so the UI can offer retry.
            is ApiResult.Failure -> degradeToRecentWindow(symbolId, interval)
            is ApiResult.NetworkError -> result
        }
    }

    /** Fallback path: reuse [candles] and adapt to [HistoryBars] (stub=true) when history is absent. */
    private suspend fun degradeToRecentWindow(symbolId: Int, interval: String): ApiResult<HistoryBars> =
        when (val c = apiCall { api.getCandles(symbolId, intervalToSeconds(interval)).bars.map { it.toDomain() } }) {
            is ApiResult.Success -> ApiResult.Success(c.data.toHistoryBars(symbolId, interval))
            is ApiResult.Failure -> c
            is ApiResult.NetworkError -> c
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

    private companion object {
        /** Map an interval LABEL to the candle interval seconds for the degraded recent-window read. */
        fun intervalToSeconds(interval: String): Int = when (interval.trim().lowercase()) {
            "1m" -> 60
            "5m" -> 300
            "15m" -> 900
            "1h" -> 3_600
            "4h" -> 14_400
            "1d" -> 86_400
            else -> 60
        }

        /** Known instrument catalogue used when `md/symbols` is unavailable/empty. */
        val FALLBACK_SYMBOLS = listOf(
            Instrument("BTCUSDC", 1, 1, 1, 100_000, false),
            Instrument("ETHUSDC", 2, 1, 1, 3_000, false),
            Instrument("SOLUSDC", 3, 1, 1, 150, false),
        )
    }
}
