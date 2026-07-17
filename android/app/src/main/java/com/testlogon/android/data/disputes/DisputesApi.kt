package com.testlogon.android.data.disputes

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-245 + DISP-021/023 — Retrofit interface + Moshi DTOs for the real billing-disputes surface.
 *
 * Payer endpoints (AND-245 / DISP-020):
 *  - GET  ui/billing/disputes                op=list_my_disputes       resp=200 ({items:[...]})
 *  - POST ui/billing/disputes                op=file_billing_dispute   req=DisputeFileIn resp=201 (DisputeOut)
 *  - GET  ui/billing/disputes/{dispute_id}   op=get_my_dispute         resp=200 (DisputeOut)
 *
 * Creator endpoints (DISP-021 / DISP-024):
 *  - GET  ui/creator/disputes                op=list_my_creator_disputes resp=200 ({items:[...]})
 *  - POST ui/creator/disputes/{id}/respond   op=respond_to_dispute_as_creator req=CreatorDisputeRespondIn resp=200
 *
 * Money is integer cents; timestamps epoch SECONDS. Session cookies + Authorization Bearer + X-CSRF-Token
 * are attached by core-network interceptors.
 */
interface DisputesApi {

    /** List my (payer) disputes (bounded by `limit`, no cursor). Idempotent GET. */
    @GET("ui/billing/disputes")
    suspend fun listDisputes(@Query("limit") limit: Int = DEFAULT_LIMIT): DisputeListDto

    /** File (open) a dispute / chargeback against a transaction (201). Non-idempotent. */
    @POST("ui/billing/disputes")
    suspend fun fileDispute(@Body body: DisputeFileInDto): DisputeDto

    /** Single dispute detail / status re-fetch. Idempotent GET. */
    @GET("ui/billing/disputes/{disputeId}")
    suspend fun getDispute(@Path("disputeId") disputeId: String): DisputeDto

    /** DISP-021: my inbound queue — disputes filed against me as creator/seller. Idempotent GET. */
    @GET("ui/creator/disputes")
    suspend fun listCreatorDisputes(@Query("limit") limit: Int = DEFAULT_LIMIT): DisputeListDto

    /** DISP-021: a single dispute I am the counterparty on. Idempotent GET. */
    @GET("ui/creator/disputes/{disputeId}")
    suspend fun getCreatorDispute(@Path("disputeId") disputeId: String): DisputeDto

    /** DISP-021: submit my rebuttal within the response window (200). Non-idempotent. */
    @POST("ui/creator/disputes/{disputeId}/respond")
    suspend fun creatorRespond(
        @Path("disputeId") disputeId: String,
        @Body body: CreatorDisputeRespondReqDto,
    ): CreatorDisputeRespondResultDto

    companion object {
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs ----

/** List envelope `{ items: [...] }` (no next_cursor). */
@JsonClass(generateAdapter = true)
data class DisputeListDto(
    @Json(name = "items") val items: List<DisputeDto> = emptyList(),
)

/**
 * DisputeFileIn. amount_cents + reason are required; the rest default server-side.
 * charge_type/charge_ref/recipient_id locate the charge for the reversal rail (DISP-010).
 */
@JsonClass(generateAdapter = true)
data class DisputeFileInDto(
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "reason") val reason: String,
    @Json(name = "reason_detail") val reasonDetail: String? = null,
    @Json(name = "charge_type") val chargeType: String? = null,
    @Json(name = "charge_ref") val chargeRef: String? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
    @Json(name = "provider") val provider: String? = null,
)

/**
 * DisputeOut. admin_notes/user_id are internal and not surfaced to end users. DISP-010/011/012
 * add charge_type/recipient/respond_by/moved_cents/creator_response.
 */
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
    @Json(name = "charge_type") val chargeType: String? = null,
    @Json(name = "charge_ref") val chargeRef: String? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
    @Json(name = "reason_detail") val reasonDetail: String? = null,
    @Json(name = "respond_by") val respondBy: Long? = null,
    @Json(name = "moved_cents") val movedCents: Long? = null,
    @Json(name = "creator_response") val creatorResponse: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "deadline_at") val deadlineAt: Long? = null,
)

/** CreatorDisputeRespondIn (DISP-021). */
@JsonClass(generateAdapter = true)
data class CreatorDisputeRespondReqDto(
    @Json(name = "response_text") val responseText: String,
    @Json(name = "evidence_files") val evidenceFiles: List<String>? = null,
)

/** Response of POST /ui/creator/disputes/{id}/respond. */
@JsonClass(generateAdapter = true)
data class CreatorDisputeRespondResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "dispute_id") val disputeId: String = "",
    @Json(name = "status") val status: String? = null,
    @Json(name = "creator_response") val creatorResponse: String? = null,
)
