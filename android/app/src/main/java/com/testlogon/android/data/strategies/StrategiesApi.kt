package com.testlogon.android.data.strategies

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * Retrofit interface for the USER-CREATED STRATEGIES / BASKETS surface (`me/strategies/(all)`).
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * core-network interceptor chain attaches the cookie session. All methods are `suspend` and return the
 * typed DTO body; a non-2xx surfaces as `retrofit2.HttpException`.
 *
 * NONE of these endpoints exist on the backend yet. The [StrategiesRepository] degrades every GET to
 * an empty-but-honest state on 404/absence and surfaces a clear error on every failed mutation (never
 * a silent success), so this contract is a forward declaration wired for graceful "pending backend" UX.
 */
interface StrategiesApi {

    @POST("me/strategies")
    suspend fun create(@Body body: UpsertStrategyRequestDto): StrategyDto

    /** Strategies AUTHORED by the caller. */
    @GET("me/strategies")
    suspend fun getMine(): StrategyListDto

    @GET("me/strategies/{id}")
    suspend fun getStrategy(@Path("id") id: String): StrategyDto

    @PUT("me/strategies/{id}")
    suspend fun update(@Path("id") id: String, @Body body: UpsertStrategyRequestDto): StrategyDto

    @POST("me/strategies/{id}/publish")
    suspend fun publish(@Path("id") id: String): StrategyDto

    /** PUBLISHED strategies to browse (the marketplace). */
    @GET("me/strategies/market")
    suspend fun getMarket(): StrategyListDto

    @GET("me/strategies/{id}/nav")
    suspend fun getNav(@Path("id") id: String): StrategyNavDto

    @GET("me/strategies/{id}/holdings")
    suspend fun getHoldings(@Path("id") id: String): StrategyHoldingsDto

    @POST("me/strategies/{id}/invest")
    suspend fun invest(@Path("id") id: String, @Body body: InvestRequestDto): StrategyAckDto

    @POST("me/strategies/{id}/redeem")
    suspend fun redeem(@Path("id") id: String, @Body body: RedeemRequestDto): StrategyAckDto

    @GET("me/strategies/{id}/position")
    suspend fun getPosition(@Path("id") id: String): InvestorPositionDto

    @GET("me/strategies/{id}/fees")
    suspend fun getFees(@Path("id") id: String): StrategyFeesDto
}
