package com.testlogon.android.data.refunds

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-244 — Retrofit interface + Moshi DTOs for the real refund-requests surface (extends the AND-223
 * billing surface). Distinct from the admin refund endpoints under `/ui/admin/refund-requests`.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/types.ts:
 *  - POST ui/billing/refund-requests              op=submit_refund_request_...  req=RefundRequestIn  resp=201 (RefundRequestOut)
 *      (openapi.index.txt L1194; params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN)
 *  - GET  ui/billing/refund-requests              op=list_my_refund_requests_... resp=200 ({items:[...]})
 *      (openapi.index.txt L1193; only `limit` query param — NO cursor)
 *  - GET  ui/billing/refund-requests/{request_id} op=get_refund_request_detail_... resp=200 (RefundRequestOut)
 *      (openapi.index.txt L1195)
 *
 * RefundRequestIn (types.ts L691): { transaction_entry_id (req), reason (req, 10..2000), amount_cents? (>=1) }.
 * RefundRequestOut (types.ts L697): required refund_request_id/status/amount_cents/currency/reason/created_at;
 * optional transaction_type/transaction_entry_id/admin_notes/completed_at/requester_user_id.
 * Money is integer cents; created_at/completed_at are epoch SECONDS. Session cookies + Authorization Bearer +
 * X-CSRF-Token are attached by the core-network interceptors (no per-method @Header).
 *
 * GAP NOTE: no Idempotency-Key param is documented and no 409 response is declared (only 201/200 + 422);
 * duplicate protection is the in-flight submit guard in the ViewModel (AND-244 §6, citations 16/17).
 */
interface RefundsApi {

    /** Submit a refund request for a transaction entry (201). Non-idempotent. */
    @POST("ui/billing/refund-requests")
    suspend fun submitRefund(@Body body: RefundRequestInDto): RefundRequestOutDto

    /** List my refund requests (bounded by `limit`, no cursor). Idempotent GET. */
    @GET("ui/billing/refund-requests")
    suspend fun listRefunds(@Query("limit") limit: Int = DEFAULT_LIMIT): RefundListDto

    /** Single refund request detail / status re-fetch. Idempotent GET. */
    @GET("ui/billing/refund-requests/{requestId}")
    suspend fun getRefund(@Path("requestId") requestId: String): RefundRequestOutDto

    companion object {
        const val DEFAULT_LIMIT = 100
    }
}

// ---- DTOs (AND-244) ----

/** RefundRequestIn (types.ts L691). amount_cents omitted/null => full refund. */
@JsonClass(generateAdapter = true)
data class RefundRequestInDto(
    @Json(name = "transaction_entry_id") val transactionEntryId: String,
    @Json(name = "reason") val reason: String,
    @Json(name = "amount_cents") val amountCents: Long? = null,
)

/** List envelope `{ items: [...] }` (no next_cursor — verified AND-244 §5). */
@JsonClass(generateAdapter = true)
data class RefundListDto(
    @Json(name = "items") val items: List<RefundRequestOutDto> = emptyList(),
)

/**
 * RefundRequestOut (types.ts L697). Only refund_request_id/status/amount_cents/currency/reason/created_at
 * are required upstream; the rest are optional/nullable.
 */
@JsonClass(generateAdapter = true)
data class RefundRequestOutDto(
    @Json(name = "refund_request_id") val refundRequestId: String,
    @Json(name = "status") val status: String,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "transaction_type") val transactionType: String? = null,
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "admin_notes") val adminNotes: String? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "requester_user_id") val requesterUserId: String? = null,
)
