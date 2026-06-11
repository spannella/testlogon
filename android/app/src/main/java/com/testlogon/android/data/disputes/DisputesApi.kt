package com.testlogon.android.data.disputes

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-245 — Retrofit interface + Moshi DTOs for the real billing-disputes surface (extends the AND-223
 * billing surface). Distinct from the admin/collab dispute endpoints.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/types.ts:
 *  - GET  ui/billing/disputes                op=list_my_disputes_...   resp=200 ({items:[...]})
 *      (openapi.index.txt L1177; params=limit,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN — NO cursor)
 *  - POST ui/billing/disputes                op=file_billing_dispute_... req=DisputeFileIn resp=201 (DisputeOut)
 *      (openapi.index.txt L1178)
 *  - GET  ui/billing/disputes/{dispute_id}   op=get_my_dispute_...     resp=200 (DisputeOut)
 *      (openapi.index.txt L1179)
 *
 * DisputeFileIn (types.ts L721): { transaction_entry_id? , amount_cents (req), currency?, reason (req),
 * provider? }. DisputeOut (types.ts L729): required dispute_id/provider/amount_cents/currency/reason/
 * status/evidence_submitted/created_at; the rest optional/nullable. Money is integer cents; timestamps
 * epoch SECONDS. NOTE: the AND-245 spec scopes itself read-only, but the orchestrator prompt requires a
 * "open a dispute" POST flow, so the file-dispute POST is included here (it is a real, declared endpoint).
 * Session cookies + Authorization Bearer + X-CSRF-Token are attached by core-network interceptors.
 */
interface DisputesApi {

    /** List my disputes (bounded by `limit`, no cursor). Idempotent GET. */
    @GET("ui/billing/disputes")
    suspend fun listDisputes(@Query("limit") limit: Int = DEFAULT_LIMIT): DisputeListDto

    /** File (open) a dispute / chargeback against a transaction (201). Non-idempotent. */
    @POST("ui/billing/disputes")
    suspend fun fileDispute(@Body body: DisputeFileInDto): DisputeDto

    /** Single dispute detail / status re-fetch. Idempotent GET. */
    @GET("ui/billing/disputes/{disputeId}")
    suspend fun getDispute(@Path("disputeId") disputeId: String): DisputeDto

    companion object {
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs (AND-245) ----

/** List envelope `{ items: [...] }` (no next_cursor — verified AND-245 §4.1). */
@JsonClass(generateAdapter = true)
data class DisputeListDto(
    @Json(name = "items") val items: List<DisputeDto> = emptyList(),
)

/**
 * DisputeFileIn (types.ts L721). amount_cents + reason are required; currency/provider default
 * server-side; transaction_entry_id is optional (the txn the dispute is filed against).
 */
@JsonClass(generateAdapter = true)
data class DisputeFileInDto(
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "reason") val reason: String,
    @Json(name = "provider") val provider: String? = null,
)

/** DisputeOut (types.ts L729). admin_notes/user_id are internal and not surfaced to the user. */
@JsonClass(generateAdapter = true)
data class DisputeDto(
    @Json(name = "dispute_id") val disputeId: String,
    @Json(name = "provider") val provider: String = "",
    @Json(name = "provider_dispute_id") val providerDisputeId: String? = null,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "evidence_submitted") val evidenceSubmitted: Boolean = false,
    @Json(name = "evidence_text") val evidenceText: String? = null,
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "admin_notes") val adminNotes: String? = null,
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "deadline_at") val deadlineAt: Long? = null,
)
