package com.testlogon.android.data.exchange

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the read-only exchange market-data (`md/ (market-data)`) endpoints.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * core-network interceptor chain attaches the cookie session. All methods are `suspend` and return
 * the typed DTO body; a non-2xx surfaces as `retrofit2.HttpException`. Symbols are addressed by the
 * numeric symbolId (1=BTCUSDC, 2=ETHUSDC, 3=SOLUSDC).
 */
interface ExchangeApi {

    @GET("md/symbols")
    suspend fun getSymbols(): SymbolsResponseDto

    @GET("md/book/{symbolId}")
    suspend fun getOrderBook(
        @Path("symbolId") symbolId: Int,
        @Query("depth") depth: Int = 20,
    ): OrderBookDto

    @GET("md/candles/{symbolId}")
    suspend fun getCandles(
        @Path("symbolId") symbolId: Int,
        @Query("interval") intervalSec: Int = 60,
    ): CandlesResponseDto

    @GET("md/trades/{symbolId}")
    suspend fun getTrades(
        @Path("symbolId") symbolId: Int,
    ): TradesResponseDto

    /**
     * Long-range HISTORICAL bars for the Analysis workbench. NEW endpoint — the backend may 404 it,
     * in which case the repository degrades to [getCandles] (recent window). [interval] is the
     * candle interval label (e.g. "1m","1h","1d"); [from]/[to] are epoch-second bounds (optional);
     * [cursor] paginates a large range.
     */
    @GET("md/history/{symbolId}")
    suspend fun getHistory(
        @Path("symbolId") symbolId: Int,
        @Query("interval") interval: String,
        @Query("from") from: Long? = null,
        @Query("to") to: Long? = null,
        @Query("cursor") cursor: String? = null,
    ): HistoryResponseDto
}
