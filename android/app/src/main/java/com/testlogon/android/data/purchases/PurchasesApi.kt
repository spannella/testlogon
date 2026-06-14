package com.testlogon.android.data.purchases

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-218 — Retrofit interface for the purchase-history (transactions) surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 * All three calls are idempotent GETs (bounded-backoff eligible). List and search return BARE JSON
 * arrays (no envelope / no server pagination); the only request controls are limit (+ status on list,
 * q on search). A null query param is omitted by Retrofit.
 *
 * Verified contract (reference/openapi.index.txt lines 1761/1763/1764; reference/src/api/endpoints/
 * purchases.ts listTransactions/searchTransactions/getTransaction):
 *  - GET ui/purchase-history/transactions            -> List of PurchaseTransactionSummary  (params limit, status)
 *  - GET ui/purchase-history/transactions/search      -> List of PurchaseTransactionSummary  (params q, limit)
 *  - GET ui/purchase-history/transactions/{txn_id}    -> PurchaseTransactionInfo
 */
interface PurchasesApi {

    @GET("ui/purchase-history/transactions")
    suspend fun listTransactions(
        @Query("limit") limit: Int? = null,
        @Query("status") status: String? = null,
    ): List<PurchaseTransactionSummaryDto>

    @GET("ui/purchase-history/transactions/search")
    suspend fun searchTransactions(
        @Query("q") q: String,
        @Query("limit") limit: Int? = null,
    ): List<PurchaseTransactionSummaryDto>

    @GET("ui/purchase-history/transactions/{txnId}")
    suspend fun getTransaction(
        @Path("txnId") txnId: String,
    ): PurchaseTransactionInfoDto

    companion object {
        /** Web client default page cap (purchases.ts / PurchaseHistory.tsx use limit: 50). */
        const val PAGE_SIZE = 50
    }
}
