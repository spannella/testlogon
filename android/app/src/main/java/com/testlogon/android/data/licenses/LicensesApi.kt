package com.testlogon.android.data.licenses

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the content-licensing hub.
 *
 * Endpoints verified against frontend/src/api/endpoints/issuedLicenses.ts, licenseRequests.ts and
 * license-revenue.ts + the referenced *Out shapes in frontend/src/api/types.ts (the OpenAPI 200 bodies
 * are untyped, so the frontend TS types are authoritative). The hub renders three read-mostly sections:
 *
 *  - Issued licenses  : GET ui/licenses/issued                (IssuedLicenseIndexItem list, cursor-paged)
 *  - Sent requests    : GET ui/licenses/requests/sent         (LicenseRequestOut list, cursor-paged)
 *  - Earned revenue   : GET ui/licenses/revenue/earned        (RevenueSummaryOut + RevenueTransactionOut)
 *
 * The request approve/deny endpoints take an owner-side content_id and operate on the RECEIVED inbox
 * (operator-style review), so they are intentionally out of scope here: the user-facing hub is read-only.
 * Session cookies / Bearer / X-CSRF-Token are attached by interceptors.
 */
interface LicensesApi {

    /** Licenses the caller has issued. [status] optionally filters; [cursor] pages forward. */
    @GET("ui/licenses/issued")
    suspend fun getIssuedLicenses(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): IssuedLicenseListDto

    /** License requests the caller has sent. [status] optionally filters; [cursor] pages forward. */
    @GET("ui/licenses/requests/sent")
    suspend fun getSentRequests(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): LicenseRequestListDto

    /** Revenue the caller has earned as a licensor (summary + recent transactions). */
    @GET("ui/licenses/revenue/earned")
    suspend fun getEarnedRevenue(
        @Query("source_type") sourceType: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): RevenueListDto
}

// ---- Issued-license DTOs ----

@JsonClass(generateAdapter = true)
data class IssuedLicenseListDto(
    val items: List<IssuedLicenseItemDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class IssuedLicenseItemDto(
    @Json(name = "issued_license_id") val issuedLicenseId: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "licensee_id") val licenseeId: String? = null,
    @Json(name = "license_mode") val licenseMode: String = "",
    val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

// ---- License-request DTOs ----

@JsonClass(generateAdapter = true)
data class LicenseRequestListDto(
    val items: List<LicenseRequestDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class LicenseRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "requester_display_name") val requesterDisplayName: String = "",
    @Json(name = "owner_display_name") val ownerDisplayName: String = "",
    val status: String = "",
    @Json(name = "proposed_terms") val proposedTerms: LicenseTermsDto? = null,
    @Json(name = "denial_reason") val denialReason: String = "",
    val message: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class LicenseTermsDto(
    @Json(name = "profit_share_pct") val profitSharePct: Double = 0.0,
    @Json(name = "fixed_cost_cents") val fixedCostCents: Long = 0,
    @Json(name = "revenue_share_pct") val revenueSharePct: Double = 0.0,
)

// ---- Revenue DTOs ----

@JsonClass(generateAdapter = true)
data class RevenueListDto(
    val summary: RevenueSummaryDto? = null,
    val transactions: List<RevenueTransactionDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class RevenueSummaryDto(
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "total_transactions") val totalTransactions: Int = 0,
    @Json(name = "last_transaction_at") val lastTransactionAt: Long? = null,
    val currency: String = "USD",
)

@JsonClass(generateAdapter = true)
data class RevenueTransactionDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "issued_license_id") val issuedLicenseId: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "source_type") val sourceType: String = "",
    @Json(name = "source_amount_cents") val sourceAmountCents: Long = 0,
    @Json(name = "split_amount_cents") val splitAmountCents: Long = 0,
    @Json(name = "split_type") val splitType: String = "",
    val currency: String = "USD",
    @Json(name = "created_at") val createdAt: Long = 0,
)
