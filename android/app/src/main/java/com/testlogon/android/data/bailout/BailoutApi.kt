package com.testlogon.android.data.bailout

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * Retrofit interface for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * core-network interceptor chain attaches the cookie session. All methods are `suspend` and return the
 * typed DTO body; a non-2xx surfaces as `retrofit2.HttpException`.
 *
 * NONE of these endpoints exist on the backend yet. [BailoutRepository] degrades every GET to an
 * empty-but-honest state on 404/absence (never fabricating distress) and surfaces a clear error on
 * every failed mutation (never a silent success), so this contract is a forward declaration wired for
 * graceful "pending backend" UX. Positions are addressed by the numeric symbolId.
 */
interface BailoutApi {

    /** The caller's distressed-but-solvent margin positions (server-authoritative). */
    @GET("me/margin/distress")
    suspend fun getDistress(): DistressResponseDto

    /** Open bailout auctions to browse (the rescuer opportunity board). */
    @GET("me/bailouts")
    suspend fun getBailouts(): BailoutListDto

    /** The bailout auction (if any) for one of the caller's positions. */
    @GET("me/positions/{symbolId}/bailout")
    suspend fun getPositionBailout(@Path("symbolId") symbolId: Int): BailoutAuctionDto

    /** Open a pre-emptive bailout auction on a distressed-but-solvent position. */
    @POST("me/positions/{symbolId}/bailout")
    suspend fun openBailout(
        @Path("symbolId") symbolId: Int,
        @Body body: OpenBailoutRequestDto,
    ): BailoutAuctionDto

    /** Inject rescue capital for a position-share (a sealed rescue bid). */
    @POST("me/bailouts/{auctionId}/bid")
    suspend fun placeBid(
        @Path("auctionId") auctionId: String,
        @Body body: BailoutBidRequestDto,
    ): BailoutAckDto

    /** Owner-only: clear the auction at the single least-dilutive clearing share. */
    @POST("me/bailouts/{auctionId}/clear")
    suspend fun clear(@Path("auctionId") auctionId: String): BailoutAuctionDto

    @GET("me/prefs/bailout")
    suspend fun getPrefs(): BailoutPrefsDto

    @PUT("me/prefs/bailout")
    suspend fun putPrefs(@Body body: BailoutPrefsDto): BailoutPrefsDto
}
