package com.testlogon.android.data.licenses

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the license-COMPLIANCE sub-screen.
 *
 * Mirrors frontend/src/api/endpoints/licenseCompliance.ts (creator-scoped subset only; the
 * admin compliance surface is out of scope). Session cookies + X-CSRF-Token are
 * attached by interceptors. Timestamps are epoch seconds (nullable Longs where the backend may omit).
 */
interface LicenseComplianceApi {

    /** Licensing health of the caller's own content (+ a roll-up summary). */
    @GET("ui/licenses/compliance/my-content")
    suspend fun getMyContentCompliance(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): CreatorComplianceListDto

    /** Compliance status record for one content item. */
    @GET("ui/licenses/compliance/content/{contentId}")
    suspend fun getContentCompliance(
        @Path("contentId") contentId: String,
    ): ComplianceStatusDto

    /** License references attached to a content item. */
    @GET("ui/licenses/compliance/content/{contentId}/refs")
    suspend fun getContentLicenseRefs(
        @Path("contentId") contentId: String,
    ): LicenseRefListDto

    /** Flags filed against a content item. */
    @GET("ui/licenses/compliance/content/{contentId}/flags")
    suspend fun getContentFlags(
        @Path("contentId") contentId: String,
        @Query("status") status: String? = null,
    ): ComplianceFlagListDto

    /** Re-run the compliance check for a content item. */
    @POST("ui/licenses/compliance/content/{contentId}/check")
    suspend fun checkContentCompliance(
        @Path("contentId") contentId: String,
        @Query("content_type") contentType: String? = null,
    ): ComplianceCheckResultDto

    /** File a licensing flag against a content item. */
    @POST("ui/licenses/compliance/flag")
    suspend fun flagContent(@Body body: FlagContentReqDto): ComplianceFlagDto
}

// ---- request DTO ----

@JsonClass(generateAdapter = true)
data class FlagContentReqDto(
    @Json(name = "content_id") val contentId: String,
    val reason: String,
    val evidence: String = "",
    @Json(name = "reporter_type") val reporterType: String = "creator",
)

// ---- my-content list ----

@JsonClass(generateAdapter = true)
data class CreatorComplianceListDto(
    val items: List<CreatorComplianceItemDto> = emptyList(),
    val summary: ComplianceSummaryDto? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreatorComplianceItemDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "compliance_status") val complianceStatus: String = "",
    @Json(name = "issue_count") val issueCount: Int = 0,
    @Json(name = "last_checked_at") val lastCheckedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class ComplianceSummaryDto(
    val total: Int = 0,
    val compliant: Int = 0,
    @Json(name = "expiring_soon") val expiringSoon: Int = 0,
    val issues: Int = 0,
    val flagged: Int = 0,
)

// ---- content detail ----

@JsonClass(generateAdapter = true)
data class ComplianceIssueDto(
    val type: String = "",
    val detail: String = "",
)

@JsonClass(generateAdapter = true)
data class ComplianceStatusDto(
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "compliance_status") val complianceStatus: String = "",
    val issues: List<ComplianceIssueDto> = emptyList(),
    @Json(name = "last_checked_at") val lastCheckedAt: Long? = null,
    @Json(name = "resolved_at") val resolvedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class LicenseRefListDto(
    val items: List<LicenseRefDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class LicenseRefDto(
    @Json(name = "license_id") val licenseId: String,
    @Json(name = "license_type") val licenseType: String = "",
    @Json(name = "license_status") val licenseStatus: String = "",
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "verified_at") val verifiedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class ComplianceFlagListDto(
    val items: List<ComplianceFlagDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class ComplianceFlagDto(
    @Json(name = "flag_id") val flagId: String,
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "reporter_type") val reporterType: String = "",
    val reason: String = "",
    val evidence: String = "",
    val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "resolution_notes") val resolutionNotes: String = "",
)

@JsonClass(generateAdapter = true)
data class ComplianceCheckResultDto(
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "compliance_status") val complianceStatus: String = "",
    val issues: List<ComplianceIssueDto> = emptyList(),
    @Json(name = "checked_at") val checkedAt: Long = 0,
)
