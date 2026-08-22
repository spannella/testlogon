package com.testlogon.android.data.tokens

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the CREATOR REVENUE-SHARE TOKEN surface (`me/tokens/(all)`).
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * core-network interceptor chain attaches the cookie session. All methods are `suspend` and return the
 * typed DTO body; a non-2xx surfaces as `retrofit2.HttpException`.
 *
 * NONE of these endpoints exist on the backend yet. The [TokensRepository] degrades every GET to an
 * empty-but-honest state on 404/absence and surfaces a clear error on every failed mutation (never a
 * silent success), so this contract is a forward declaration wired for graceful "pending backend" UX.
 */
interface TokensApi {

    @POST("me/tokens")
    suspend fun mint(@Body body: MintTokenRequestDto): TokenDto

    /** Tokens ISSUED by the caller. */
    @GET("me/tokens")
    suspend fun getIssued(): TokenListDto

    /** LISTED tokens to browse (the market). */
    @GET("me/tokens/market")
    suspend fun getMarket(): TokenListDto

    /**
     * OPEN IPO token auctions (the discovery feed of tokens currently raising via a sealed-bid IPO).
     * OPTIONAL / not deployed on every backend: the [TokensRepository] degrades a 404 to an empty list.
     */
    @GET("me/tokens/auctions")
    suspend fun getOpenAuctions(): TokenAuctionListDto

    @GET("me/tokens/{id}")
    suspend fun getToken(@Path("id") id: String): TokenDto

    @GET("me/tokens/{id}/captable")
    suspend fun getCapTable(@Path("id") id: String): TokenCapTableDto

    @POST("me/tokens/{id}/list")
    suspend fun list(@Path("id") id: String, @Body body: ListTokenRequestDto): TokenAuctionDto

    @GET("me/tokens/{id}/auction")
    suspend fun getAuction(@Path("id") id: String): TokenAuctionDto

    @POST("me/tokens/{id}/auction/bid")
    suspend fun placeBid(@Path("id") id: String, @Body body: PlaceBidRequestDto): TokenAckDto

    @POST("me/tokens/{id}/auction/clear")
    suspend fun clearAuction(@Path("id") id: String): TokenAuctionDto

    @GET("me/tokens/{id}/revenue")
    suspend fun getRevenue(@Path("id") id: String): TokenRevenueDto

    @POST("me/tokens/{id}/revenue/claim")
    suspend fun claimRevenue(@Path("id") id: String): TokenAckDto

    @GET("me/tokens/{id}/upkeep")
    suspend fun getUpkeep(@Path("id") id: String): TokenUpkeepDto

    @POST("me/tokens/{id}/upkeep/pay")
    suspend fun payUpkeep(@Path("id") id: String): TokenAckDto
}
