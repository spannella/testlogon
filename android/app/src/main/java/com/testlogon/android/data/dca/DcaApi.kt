package com.testlogon.android.data.dca

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the DCA / RECURRING-BUYS surface (schedule recurring buys of a symbol / creator
 * token / strategy fund, funded from the USD cash wallet). Mirrors the web data contract EXACTLY. Paths
 * are relative (no leading slash) so they resolve against the shared authenticated Retrofit base URL; the
 * session cookie + CSRF header are attached by the core-network interceptor chain.
 *
 * The periodic EXECUTION of a plan is a SERVER-SIDE runner; this client owns only plan CRUD + schedule
 * preview + history. Every read DEGRADES on 404 (the me/dca backend runner is pending) to an honest
 * empty/pending state; mutations pass a rejection (or undeployed 404) through as a clear error, never a
 * silent success. All methods are suspend; a non-2xx surfaces as retrofit2.HttpException.
 */
interface DcaApi {

    /** GET me/dca/plans -> {plans:[...]}. Read degrades on 404. */
    @GET("me/dca/plans")
    suspend fun plans(): DcaPlansEnvelopeDto

    /** POST me/dca/plans {plan fields} -> the created plan. */
    @Headers("Content-Type: application/json")
    @POST("me/dca/plans")
    suspend fun createPlan(@Body body: CreateDcaPlanRequestDto): DcaPlanDto

    /** POST me/dca/plans/{id}/pause -> the updated plan. */
    @POST("me/dca/plans/{id}/pause")
    suspend fun pause(@Path("id") id: String): DcaPlanDto

    /** POST me/dca/plans/{id}/resume -> the updated plan. */
    @POST("me/dca/plans/{id}/resume")
    suspend fun resume(@Path("id") id: String): DcaPlanDto

    /** POST me/dca/plans/{id}/cancel -> the updated plan. */
    @POST("me/dca/plans/{id}/cancel")
    suspend fun cancel(@Path("id") id: String): DcaPlanDto

    /** GET me/dca/plans/{id}/history -> {runs:[...]}. Read degrades on 404. */
    @GET("me/dca/plans/{id}/history")
    suspend fun history(@Path("id") id: String): DcaHistoryEnvelopeDto

    /** POST me/dca/plans/{id}/run-now -> the run result (best-effort; runner-owned). */
    @POST("me/dca/plans/{id}/run-now")
    suspend fun runNow(@Path("id") id: String): DcaRunNowResultDto
}

// ---- Wire DTOs (codegen-only Moshi; numerics lenient; every field defaulted so a partial shape parses) ----

@JsonClass(generateAdapter = true)
data class DcaPlansEnvelopeDto(
    @Json(name = "plans") val plans: List<DcaPlanDto>? = null,
)

/** The plan target (what the recurring buy purchases). */
@JsonClass(generateAdapter = true)
data class DcaTargetDto(
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "id") val id: String? = null,
    @Json(name = "label") val label: String? = null,
)

@JsonClass(generateAdapter = true)
data class DcaPlanDto(
    @Json(name = "plan_id") val planId: String? = null,
    @Json(name = "target") val target: DcaTargetDto? = null,
    @LenientLong @Json(name = "amount_cents") val amountCents: Long? = null,
    @Json(name = "frequency") val frequency: String? = null,
    @LenientInt @Json(name = "day_of_week") val dayOfWeek: Int? = null,
    @LenientInt @Json(name = "day_of_month") val dayOfMonth: Int? = null,
    @LenientLong @Json(name = "start_ts") val startTs: Long? = null,
    @LenientLong @Json(name = "end_ts") val endTs: Long? = null,
    @LenientLong @Json(name = "total_budget_cents") val totalBudgetCents: Long? = null,
    @Json(name = "funding") val funding: String? = null,
    @Json(name = "status") val status: String? = null,
    @LenientLong @Json(name = "next_run_ts") val nextRunTs: Long? = null,
    @LenientLong @Json(name = "spent_cents") val spentCents: Long? = null,
    @LenientInt @Json(name = "buys_count") val buysCount: Int? = null,
    @LenientLong @Json(name = "created_ts") val createdTs: Long? = null,
)

/** Body for POST me/dca/plans. Mirrors the web create contract. */
@JsonClass(generateAdapter = true)
data class CreateDcaPlanRequestDto(
    @Json(name = "target") val target: DcaTargetDto,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "frequency") val frequency: String,
    @Json(name = "day_of_week") val dayOfWeek: Int? = null,
    @Json(name = "day_of_month") val dayOfMonth: Int? = null,
    @Json(name = "start_ts") val startTs: Long,
    @Json(name = "end_ts") val endTs: Long? = null,
    @Json(name = "total_budget_cents") val totalBudgetCents: Long? = null,
    @Json(name = "funding") val funding: String = "usd_wallet",
)

@JsonClass(generateAdapter = true)
data class DcaHistoryEnvelopeDto(
    @Json(name = "runs") val runs: List<DcaRunDto>? = null,
)

@JsonClass(generateAdapter = true)
data class DcaRunDto(
    // ts is epoch SECONDS on the wire (matching the other money surfaces); converted to ms at mapping.
    @LenientLong @Json(name = "ts") val ts: Long? = null,
    @LenientLong @Json(name = "amount_cents") val amountCents: Long? = null,
    // Quantity filled in base units, when executed (lenient: may arrive as a quoted number).
    @LenientLong @Json(name = "filled_qty") val filledQty: Long? = null,
    // Fill price in CENTS, when executed.
    @LenientLong @Json(name = "price") val price: Long? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "note") val note: String? = null,
)

@JsonClass(generateAdapter = true)
data class DcaRunNowResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)
