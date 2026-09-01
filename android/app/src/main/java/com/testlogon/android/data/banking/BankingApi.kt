package com.testlogon.android.data.banking

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the OpenBankProject banking-accounts surface (prefix `/ui/banking`,
 * ACC-001..ACC-004). Paths are relative (no leading slash) so they resolve against the shared Retrofit
 * base URL; the session cookie + CSRF header are attached by the core-network interceptor chain.
 *
 * The whole router is FEATURE-FLAG-GATED server-side (`open_bank_project_enabled AND
 * banking_accounts_enabled`). When the flags are off the router is not registered and EVERY route
 * returns a true FastAPI 404. [BankingRepository] folds that 404 (and any HTTP error on a read) into a
 * soft "unavailable" success so the UI degrades to an honest empty state; mutations still surface the
 * error. Mirrors `frontend/src/api/endpoints/bankAccounts.ts`.
 */
interface BankingApi {

    // ─── Banks (ACC-001) ────────────────────────────────────────────────────

    @GET("ui/banking/banks")
    suspend fun listBanks(): BankListDto

    // ─── Accounts (ACC-001) ─────────────────────────────────────────────────

    @GET("ui/banking/accounts")
    suspend fun listAccounts(): AccountListDto

    @GET("ui/banking/accounts/{account_id}")
    suspend fun getAccount(@Path("account_id") accountId: String): AccountDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/banking/accounts/{account_id}")
    suspend fun updateAccount(
        @Path("account_id") accountId: String,
        @Body body: AccountUpdateDto,
    ): AccountDto

    @DELETE("ui/banking/accounts/{account_id}")
    suspend fun deleteAccount(@Path("account_id") accountId: String)

    @GET("ui/banking/accounts/{account_id}/balance")
    suspend fun getBalance(@Path("account_id") accountId: String): AccountBalanceDto

    // ─── Transactions (ACC-002) ─────────────────────────────────────────────

    @GET("ui/banking/accounts/{account_id}/transactions")
    suspend fun listTransactions(
        @Path("account_id") accountId: String,
        @Query("from") from: String? = null,
        @Query("to") to: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("order") order: String? = null,
    ): TransactionListDto

    @GET("ui/banking/accounts/{account_id}/transactions/{transaction_id}")
    suspend fun getTransaction(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
    ): TransactionDto

    // ─── Transaction metadata (ACC-003) ─────────────────────────────────────

    @GET("ui/banking/accounts/{account_id}/transactions/{transaction_id}/metadata")
    suspend fun getTransactionMetadata(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
    ): TransactionMetadataDto

    @Headers("Content-Type: application/json")
    @PUT("ui/banking/accounts/{account_id}/transactions/{transaction_id}/narrative")
    suspend fun putNarrative(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Body body: PutNarrativeDto,
    ): NarrativeDto

    @Headers("Content-Type: application/json")
    @PUT("ui/banking/accounts/{account_id}/transactions/{transaction_id}/geotag")
    suspend fun putGeotag(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Body body: PutGeotagDto,
    ): GeotagDto

    @Headers("Content-Type: application/json")
    @POST("ui/banking/accounts/{account_id}/transactions/{transaction_id}/tags")
    suspend fun addTag(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Body body: AddTagDto,
    ): TransactionTagDto

    @DELETE("ui/banking/accounts/{account_id}/transactions/{transaction_id}/tags/{tag_id}")
    suspend fun removeTag(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Path("tag_id") tagId: String,
    )

    @Headers("Content-Type: application/json")
    @POST("ui/banking/accounts/{account_id}/transactions/{transaction_id}/comments")
    suspend fun addComment(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Body body: AddCommentDto,
    ): TransactionCommentDto

    @DELETE("ui/banking/accounts/{account_id}/transactions/{transaction_id}/comments/{comment_id}")
    suspend fun deleteComment(
        @Path("account_id") accountId: String,
        @Path("transaction_id") transactionId: String,
        @Path("comment_id") commentId: String,
    )

    // ─── Account holders (ACC-004) ──────────────────────────────────────────

    @GET("ui/banking/accounts/{account_id}/holders")
    suspend fun listHolders(@Path("account_id") accountId: String): AccountHoldersDto
}
