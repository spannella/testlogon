package com.testlogon.android.data.licenses

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * Retrofit interface for the dedicated license-REVENUE sub-screen (earned / paid / split calculator).
 *
 * Mirrors frontend/src/api/endpoints/license-revenue.ts (user endpoints only; admin platform revenue is
 * out of scope). Reuses [RevenueListDto]/[RevenueSummaryDto] from LicensesApi for earned/paid, adding a
 * fuller transaction DTO ([FullRevenueTxnDto], carries counterparty + source amount) and the split
 * calculator. Session cookies + X-CSRF-Token are attached by interceptors.
 */
interface LicenseRevenueExtrasApi {

    /** Revenue the caller earned as a licensor. */
    @GET("ui/licenses/revenue/earned")
    suspend fun getEarned(
        @Query("source_type") sourceType: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): FullRevenueListDto

    /** Revenue the caller paid as a licensee. */
    @GET("ui/licenses/revenue/paid")
    suspend fun getPaid(
        @Query("source_type") sourceType: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): FullRevenueListDto

    /** Preview a revenue split for a hypothetical source amount + terms. */
    @GET("ui/licenses/revenue/calculate")
    suspend fun calculate(
        @Query("amount") amount: Long,
        @Query("revenue_share_pct") revenueSharePct: Int? = null,
        @Query("profit_share_pct") profitSharePct: Int? = null,
        @Query("fixed_cost_cents") fixedCostCents: Long? = null,
    ): RevenueSplitPreviewDto
}

@JsonClass(generateAdapter = true)
data class FullRevenueListDto(
    val summary: RevenueSummaryDto? = null,
    val transactions: List<FullRevenueTxnDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class FullRevenueTxnDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "issued_license_id") val issuedLicenseId: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "counterparty_id") val counterpartyId: String = "",
    @Json(name = "source_type") val sourceType: String = "",
    @Json(name = "source_amount_cents") val sourceAmountCents: Long = 0,
    @Json(name = "split_amount_cents") val splitAmountCents: Long = 0,
    @Json(name = "split_type") val splitType: String = "",
    val currency: String = "USD",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class RevenueSplitPreviewDto(
    @Json(name = "source_amount_cents") val sourceAmountCents: Long = 0,
    @Json(name = "platform_fee_cents") val platformFeeCents: Long = 0,
    @Json(name = "revenue_share_cents") val revenueShareCents: Long = 0,
    @Json(name = "profit_share_cents") val profitShareCents: Long = 0,
    @Json(name = "total_licensor_share_cents") val totalLicensorShareCents: Long = 0,
    @Json(name = "licensee_net_cents") val licenseeNetCents: Long = 0,
)
