package com.testlogon.android.data.admin.email

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the ADMIN-EMAIL management surface (router
 * app/routers/admin_email.py, prefix `/ui/admin/email`, all `require_admin_or_root`).
 *
 * Mirrors the web adminEmail endpoints. This adds ONLY the parts NOT already covered by the AND-404
 * READ-ONLY delivery dashboard (`com.testlogon.android.data.admin.MessagingDashboardApi`, which already
 * serves `/dashboard/stats` + `/deliveries`): namely the campaign-EMAIL-TEMPLATE CRUD and the
 * SUPPRESSED-list management (list + admin unsuppress), plus the plain `/stats` window used here for a
 * compact header. Do NOT duplicate the AND-404 dashboard.
 *
 * All routes are admin-gated on the server (`require_admin_or_root`) so a non-admin gets 403; the
 * template routes additionally `_require_campaign_templates_enabled()` -> 404 when the flag is off, so
 * the repo degrades-on-404 (reads honest-empty). Session cookie / Bearer / X-CSRF-Token are attached by
 * the shared interceptors; paths are relative (base URL carries the trailing slash). Timestamps are
 * epoch-SECONDS (Long).
 */
interface AdminEmailApi {

    // ---- Stats (compact header; days window) ----

    @GET("ui/admin/email/stats")
    suspend fun getStats(@Query("days") days: Int = DEFAULT_DAYS): EmailStatsRawDto

    // ---- Suppressed list ----

    @GET("ui/admin/email/suppressed")
    suspend fun listSuppressed(@Query("limit") limit: Int = DEFAULT_LIMIT): SuppressionListDto

    /** Admin override: remove an address from the suppression list. `email` is a `{email:path}` arg. */
    @DELETE("ui/admin/email/suppressed/{email}")
    suspend fun unsuppress(@Path("email", encoded = true) email: String): UnsuppressRespDto

    // ---- Campaign email templates (CRUD) ----

    @GET("ui/admin/email/campaign-templates")
    suspend fun listTemplates(): List<CampaignTemplateDto>

    @POST("ui/admin/email/campaign-templates")
    suspend fun createTemplate(@Body body: CampaignTemplateCreateDto): CampaignTemplateDto

    @PATCH("ui/admin/email/campaign-templates/{templateId}")
    suspend fun updateTemplate(
        @Path("templateId") templateId: String,
        @Body body: CampaignTemplateUpdateDto,
    ): CampaignTemplateDto

    @DELETE("ui/admin/email/campaign-templates/{templateId}")
    suspend fun deleteTemplate(@Path("templateId") templateId: String)

    companion object {
        const val DEFAULT_DAYS = 7
        const val DEFAULT_LIMIT = 100
    }
}

// ---- Stats DTO (get_delivery_stats shape; rates are 0-100 percentages) ----

@JsonClass(generateAdapter = true)
data class EmailStatsRawDto(
    @Json(name = "sent") val sent: Int = 0,
    @Json(name = "delivered") val delivered: Int = 0,
    @Json(name = "bounced") val bounced: Int = 0,
    @Json(name = "complained") val complained: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
    @Json(name = "suppressed") val suppressed: Int = 0,
    @Json(name = "total") val total: Int = 0,
    @Json(name = "delivery_rate") val deliveryRate: Double = 0.0,
    @Json(name = "bounce_rate") val bounceRate: Double = 0.0,
    @Json(name = "complaint_rate") val complaintRate: Double = 0.0,
    @Json(name = "period_days") val periodDays: Int = AdminEmailApi.DEFAULT_DAYS,
)

// ---- Suppression DTOs (SUPPRESS# item: email/reason/status/suppressed_at) ----

@JsonClass(generateAdapter = true)
data class SuppressionItemDto(
    @Json(name = "email") val email: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "suppressed_at") val suppressedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class SuppressionListDto(
    @Json(name = "items") val items: List<SuppressionItemDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UnsuppressRespDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "email") val email: String? = null,
)

// ---- Campaign template DTOs (CampaignEmailTemplateOut = base template + campaign fields) ----

@JsonClass(generateAdapter = true)
data class CampaignTemplateDto(
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "channel") val channel: String = "campaign",
    @Json(name = "name") val name: String = "",
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "body") val body: String = "",
    @Json(name = "variables") val variables: List<String>? = null,
    @Json(name = "active") val active: Boolean = true,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "merge_fields") val mergeFields: List<String>? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "updated_by") val updatedBy: String? = null,
)

@JsonClass(generateAdapter = true)
data class CampaignTemplateCreateDto(
    @Json(name = "name") val name: String,
    @Json(name = "subject") val subject: String,
    @Json(name = "body") val body: String,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "merge_fields") val mergeFields: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CampaignTemplateUpdateDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "merge_fields") val mergeFields: List<String>? = null,
    @Json(name = "active") val active: Boolean? = null,
)
