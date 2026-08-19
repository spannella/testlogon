package com.testlogon.android.data.custody

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * Retrofit interface for the PRODUCTION custody surface (the me/custody endpoints). The exchange edge
 * proxies these to the MPC gateway. Paths are relative (no leading slash) so they resolve against the
 * shared Retrofit base URL; the session cookie + CSRF header are attached by the core-network
 * interceptor chain. All methods are suspend and return the typed DTO; a non-2xx surfaces as
 * retrofit2.HttpException.
 *
 * The custody<->trading bridge is now FOUR real routes (fund/settle x spot/margin). The old single
 * POST me/custody/transfer no longer exists.
 */
interface CustodyApi {

    /** Vault + tier + per-asset balances (vault auto-provisioned server-side). */
    @GET("me/custody/balance")
    suspend fun balance(): BalanceDto

    /** Per-CHAIN deposit address (EVM chains share one address). */
    @GET("me/custody/deposit-address")
    suspend fun depositAddress(@Query("chain") chain: Int): DepositAddressDto

    /**
     * Recent scanned incoming transfers into the vault. NOT deployed on every backend: a 404 is handled
     * by the repository as a graceful "unavailable" empty state.
     */
    @GET("me/custody/deposits")
    suspend fun getDeposits(): CustodyDepositsDto

    /** Submit a withdrawal intent; the gateway signs, holds for approval, or blocks/rejects it. */
    @Headers("Content-Type: application/json")
    @POST("me/custody/withdraw")
    suspend fun withdraw(@Body body: WithdrawRequestDto): WithdrawResultDto

    // ==== Sub-accounts + transfers ====

    /**
     * List the caller's sub-account vaults ({label, vault}). NOT deployed on every backend -> a 404 is
     * handled by the repository as a graceful "unavailable" empty state.
     */
    @GET("me/custody/subaccounts")
    suspend fun getSubAccounts(): SubAccountsDto

    /** Create a named sub-account vault under the caller's base vault (201 {created, label, vault}). */
    @Headers("Content-Type: application/json")
    @POST("me/custody/subaccounts")
    suspend fun createSubAccount(@Body body: CreateSubAccountDto): CreateSubAccountResultDto

    /** Move an asset between two of the caller's OWN sub-account vaults (REAL; echoes new balances). */
    @Headers("Content-Type: application/json")
    @POST("me/custody/subaccounts/transfer")
    suspend fun subAccountTransfer(@Body body: SubAccountTransferDto): SubAccountTransferResultDto

    // ==== Custody <-> trading bridge (four real routes) ====

    /** Move custody vault value INTO the exchange spot ledger. */
    @Headers("Content-Type: application/json")
    @POST("me/custody/fund-spot")
    suspend fun fundSpot(@Body body: BridgeRequestDto): FundResultDto

    /** Move spot-ledger value BACK into the custody vault (422 when insufficient spot available). */
    @Headers("Content-Type: application/json")
    @POST("me/custody/settle-spot")
    suspend fun settleSpot(@Body body: BridgeRequestDto): SettleResultDto

    /** Move custody vault value INTO the margin ledger (422 with reason on rejection). */
    @Headers("Content-Type: application/json")
    @POST("me/custody/fund-margin")
    suspend fun fundMargin(@Body body: BridgeRequestDto): FundResultDto

    /** Move margin-ledger value BACK into the custody vault (422 with reason on rejection). */
    @Headers("Content-Type: application/json")
    @POST("me/custody/settle-margin")
    suspend fun settleMargin(@Body body: BridgeRequestDto): SettleResultDto
    // ==== Staking (custody-gated; real gateway-backed). 404/403 -> repository degrades to unavailable. ====

    /** Stakeable providers (chain/protocol staking contracts). */
    @GET("me/staking/providers")
    suspend fun stakingProviders(): StakingProvidersDto

    /** The caller's open staking positions (principal/rewards/total per position). */
    @GET("me/staking/positions")
    suspend fun stakingPositions(): StakingPositionsDto

    /** Stake an amount with a provider (custody value -> staking contract). */
    @Headers("Content-Type: application/json")
    @POST("me/staking/stake")
    suspend fun stake(@Body body: StakeRequestBodyDto): StakeAckDto
}
