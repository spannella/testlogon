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
}
