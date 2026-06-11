package com.testlogon.android.data.payouts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-261 — Retrofit interface + Moshi DTOs for the READ-ONLY bulk/batch payout admin surface.
 *
 * VERIFIED against reference/openapi.index.txt (lines 654-655) + reference/openapi.pretty.json
 * (components.schemas.BulkBatchOut L13013, BulkBatchItem L12980) + reference/src/api/endpoints/
 * bulkPayoutTools.ts (BASE = "/ui/admin/bulk-payouts", listBatches/getBatch).
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET ui/admin/bulk-payouts/batches            op=bulk_list_batches_...   resp=200: (bare BulkBatchOut[] per bulkPayoutTools.ts) params=none
 *  - GET ui/admin/bulk-payouts/batches/{batch_id} op=bulk_get_batch_...      resp=200:BulkBatchOut;422:HTTPValidationError  params=batch_id
 *
 * READ-ONLY: this app surfaces ONLY the two GET batch views. The backend ALSO exposes mutating
 * POST .../preview and POST .../execute (BulkPreviewIn/BulkExecuteIn) and a GET .../eligible — those are
 * DELIBERATELY NOT mapped here (AND-261 is read-only; any future execute path must route through the
 * BillingAuthorizer stub + a flag, mirroring PayoutSetupRepository.requestPayout). The list endpoint
 * returns a BARE JSON array (no page wrapper, no cursor); the detail returns one batch with its line
 * items EMBEDDED in `items` (there is NO separate .../items endpoint). All money is integer cents;
 * `created_at` is an INTEGER epoch (NOT ISO). No batch-level currency field exists (defaults to USD).
 *
 * NOTE (admin scope): these are admin-tagged routes. Whether the current mobile-creator session is
 * authorized is a server concern; a 403/422 surfaces as a normal ApiResult error (see repository).
 */
interface BulkPayoutsApi {

    /** Bare JSON array of batch summaries (no query params, no pagination). Idempotent GET. */
    @GET("ui/admin/bulk-payouts/batches")
    suspend fun getBatches(): List<PayoutBatchDto>

    /** One batch including its embedded line items (no second request). Idempotent GET. */
    @GET("ui/admin/bulk-payouts/batches/{batch_id}")
    suspend fun getBatch(@Path("batch_id") batchId: String): PayoutBatchDto
}

// ---- DTOs (AND-261) ----

/**
 * Mirrors components.schemas.BulkBatchOut (L13013). Required: batch_id, created_at, kind, status,
 * item_count, total_cents; success_count/failure_count default 0; created_by/items nullable/empty.
 * The defensive defaults tolerate the flaky dev host but are NOT a contract relaxation.
 */
@JsonClass(generateAdapter = true)
data class PayoutBatchDto(
    @Json(name = "batch_id") val batchId: String,
    @Json(name = "kind") val kind: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "item_count") val itemCount: Int = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "success_count") val successCount: Int = 0,
    @Json(name = "failure_count") val failureCount: Int = 0,
    @Json(name = "created_at") val createdAtEpochSeconds: Long? = null,
    @Json(name = "created_by") val createdBy: String? = null,
    @Json(name = "items") val items: List<PayoutBatchItemDto> = emptyList(),
)

/**
 * Mirrors components.schemas.BulkBatchItem (L12980). Required: ref_id, amount_cents, status;
 * recipient/reason default "".
 */
@JsonClass(generateAdapter = true)
data class PayoutBatchItemDto(
    @Json(name = "ref_id") val refId: String,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "status") val status: String = "",
    @Json(name = "recipient") val recipient: String = "",
    @Json(name = "reason") val reason: String = "",
)
