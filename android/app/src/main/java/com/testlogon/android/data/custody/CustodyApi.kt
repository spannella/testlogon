package com.testlogon.android.data.custody

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the session-authed custody surface. Paths are relative (no leading slash)
 * so they resolve against the shared Retrofit base URL; the session cookie + CSRF header are attached
 * by the core-network interceptor chain. All methods are suspend and return the typed DTO; a non-2xx
 * surfaces as retrofit2.HttpException (403 on officer-only routes for a non-admin caller; 425 timelock
 * / 409 under-approved on release).
 */
interface CustodyApi {

    @GET("ui/custody/assets")
    suspend fun assets(): List<CustodyAssetDto>

    @GET("ui/custody/deposit-address")
    suspend fun depositAddress(
        @Query("asset") asset: String,
        @Query("chain") chain: String,
    ): CustodyDepositAddressDto

    @GET("ui/custody/deposits")
    suspend fun deposits(): List<CustodyDepositDto>

    @Headers("Content-Type: application/json")
    @POST("ui/custody/withdrawals")
    suspend fun createWithdrawal(@Body body: CustodyWithdrawalRequestDto): CustodyWithdrawalResultDto

    @GET("ui/custody/withdrawals")
    suspend fun withdrawals(): List<CustodyWithdrawalDto>

    @GET("ui/custody/withdrawals/{id}")
    suspend fun withdrawal(@Path("id") id: String): CustodyWithdrawalDto

    // Officer / admin (403 for a non-admin caller).

    @GET("ui/custody/approvals")
    suspend fun approvals(): List<CustodyWithdrawalDto>

    @Headers("Content-Type: application/json")
    @POST("ui/custody/withdrawals/{id}/approve")
    suspend fun approve(
        @Path("id") id: String,
        @Body body: CustodyApproveRequestDto,
    ): CustodyApproveResultDto

    @POST("ui/custody/withdrawals/{id}/release")
    suspend fun release(@Path("id") id: String): CustodyReleaseResultDto

    @GET("ui/custody/audit")
    suspend fun audit(): CustodyAuditDto

    @GET("ui/custody/audit/verify")
    suspend fun auditVerify(): CustodyAuditVerifyDto
}
