package com.testlogon.android.data.purchases

import com.testlogon.android.data.tracking.CarrierTrackingViewDto
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-218 — Retrofit interface for the purchase-history (transactions) surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 * All read calls are idempotent GETs (bounded-backoff eligible). List and search return BARE JSON
 * arrays (no envelope / no server pagination); the only request controls are limit (+ status on list,
 * q on search). A null query param is omitted by Retrofit.
 *
 * Verified contract (reference/openapi.index.txt lines 1761/1763/1764; reference/src/api/endpoints/
 * purchases.ts listTransactions/searchTransactions/getTransaction; app/routers/purchase_history.py):
 *  - GET ui/purchase-history/transactions            -> List of PurchaseTransactionSummary  (params limit, status)
 *  - GET ui/purchase-history/transactions/search      -> List of PurchaseTransactionSummary  (params q, limit)
 *  - GET ui/purchase-history/transactions/{txn_id}    -> PurchaseTransactionInfo
 *
 * AND-218-extras — the transaction-detail extras (purchase_history.py :126/:181/:190):
 *  - GET ui/purchase-history/transactions/{txn_id}/tracking -> CarrierTrackingView (data/tracking DTO,
 *      reused so there is one carrier-tracking wire model; data/tracking's TrackingApi also serves it).
 *  - GET ui/purchase-history/transactions/{txn_id}/events   -> { txn_id, events: [...] } (envelope)
 *  - GET ui/purchase-history/transactions/{txn_id}/receipt  -> ReceiptLinkOut
 * All three degrade on 404 in the repository / VM (a txn with no shipment / no events / no receipt yet).
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

    /**
     * ECOMX-42 (B6) — the buyer confirms delivery of their order. Drives the order + txn to
     * COMPLETED. Owner-scoped (the txn PK is the caller). Returns the refreshed txn info.
     */
    @POST("ui/purchase-history/transactions/{txnId}/confirm-received")
    suspend fun confirmReceived(
        @Path("txnId") txnId: String,
    ): PurchaseTransactionInfoDto

    /**
     * AND-218-extras — carrier/shipment tracking (purchase_history.py :126). Reuses the AND-215
     * [CarrierTrackingViewDto] wire model so there is a single carrier-tracking contract; the
     * order-detail screen's shipment timeline consumes this (via [PurchasesRepository.tracking]).
     */
    @GET("ui/purchase-history/transactions/{txnId}/tracking")
    suspend fun getTracking(
        @Path("txnId") txnId: String,
    ): CarrierTrackingViewDto

    /** AND-218-extras — the transaction event timeline envelope (purchase_history.py :181). */
    @GET("ui/purchase-history/transactions/{txnId}/events")
    suspend fun getEvents(
        @Path("txnId") txnId: String,
        @Query("limit") limit: Int? = null,
    ): PurchaseEventsResponseDto

    /** AND-218-extras — the receipt link for the transaction (purchase_history.py :190). */
    @GET("ui/purchase-history/transactions/{txnId}/receipt")
    suspend fun getReceipt(
        @Path("txnId") txnId: String,
    ): PurchaseReceiptDto

    companion object {
        /** Web client default page cap (purchases.ts / PurchaseHistory.tsx use limit: 50). */
        const val PAGE_SIZE = 50

        /** Default cap for the event timeline (backend allows 1..200). */
        const val EVENTS_LIMIT = 50
    }
}
