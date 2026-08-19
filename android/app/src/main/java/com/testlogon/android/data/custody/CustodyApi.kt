package com.testlogon.android.data.custody

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * Retrofit interface for the PRODUCTION custody surface (the me/custody endpoints). The exchange edge proxies
 * these to the MPC gateway. Paths are relative (no leading slash) so they resolve against the shared
 * Retrofit base URL; the session cookie + CSRF header are attached by the core-network interceptor
 * chain. All methods are suspend and return the typed DTO; a non-2xx surfaces as
 * retrofit2.HttpException.
 *
 * Only three endpoints exist on this backend — there is NO history / deposits list / approvals / audit.
 */
interface CustodyApi {

    /** Vault + tier + per-asset balances (vault auto-provisioned server-side). */
    @GET("me/custody/balance")
    suspend fun balance(): BalanceDto

    /** Per-CHAIN deposit address (EVM chains share one address). */
    @GET("me/custody/deposit-address")
    suspend fun depositAddress(@Query("chain") chain: Int): DepositAddressDto

    /**
     * Recent scanned incoming transfers into the vault (newest first). NOT deployed on every backend:
     * a 404 is handled by the repository as a graceful "unavailable" empty state.
     */
    @GET("me/custody/deposits")
    suspend fun getDeposits(): CustodyDepositsDto

    /** Submit a withdrawal intent; the gateway signs, holds for approval, or blocks/rejects it. */
    @Headers("Content-Type: application/json")
    @POST("me/custody/withdraw")
    suspend fun withdraw(@Body body: WithdrawRequestDto): WithdrawResultDto
}
