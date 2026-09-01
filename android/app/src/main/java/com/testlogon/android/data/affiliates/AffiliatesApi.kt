package com.testlogon.android.data.affiliates

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-265 — Retrofit interface + Moshi DTOs for the real affiliate-links surface.
 *
 * Verified against reference/openapi.index.txt (line 881, list_links_ui_affiliates_links_get) and
 * reference/src/api/endpoints/affiliates.ts: AffiliateLinkOut / AffiliateLinkListOut / AffiliateLinkCreateIn
 * (the OpenAPI 200 body is untyped `schema: {}`, so the frontend interface is authoritative). The GET
 * (ui/affiliates/links) backs the dashboard; a POST creates a link and a DELETE revokes one — the same
 * three operations the web dashboard exposes. The earnings region is aggregated client-side over links[]
 * (there is deliberately no summary endpoint consumed here).
 *
 * Money: revenue_cents / commission_earned_cents are integer cents. commission_percent /
 * conversion_rate_pct are display-only PERCENTAGES (legitimately non-integer) and never enter the money
 * graph. Timestamps are epoch SECONDS (web does `new Date(ts * 1000)`). Session/CSRF/Bearer are attached
 * by core-network interceptors; operator-only user_sub / X-SESSION-ID params are NOT sent.
 */
interface AffiliatesApi {

    /** Affiliate links + per-link metrics. OpenAPI: list_links_ui_affiliates_links_get. */
    @GET("ui/affiliates/links")
    suspend fun getLinks(): AffiliateLinksDto

    /**
     * Create an affiliate link. Backend: POST ui/affiliates/links (201). target_id is required server-side
     * (400 if blank); the client pre-validates via [AffiliateMath.validateCreate]. Returns the created
     * link in the same per-link shape as the list rows.
     */
    @POST("ui/affiliates/links")
    suspend fun createLink(@Body body: AffiliateLinkCreateRequest): AffiliateLinkDto

    /** Revoke an affiliate link. Backend: DELETE ui/affiliates/links/{link_id} -> { ok, link_id }. */
    @DELETE("ui/affiliates/links/{linkId}")
    suspend fun deleteLink(@Path("linkId") linkId: String): AffiliateDeleteDto
}

// ---- DTOs (AND-265) ----

@JsonClass(generateAdapter = true)
data class AffiliateLinksDto(
    val links: List<AffiliateLinkDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AffiliateLinkDto(
    @Json(name = "link_id") val linkId: String,
    @Json(name = "affiliate_user_id") val affiliateUserId: String = "",
    @Json(name = "product_owner_id") val productOwnerId: String = "",
    @Json(name = "target_type") val targetType: String = "",
    @Json(name = "target_id") val targetId: String = "",
    @Json(name = "target_name") val targetName: String = "",
    @Json(name = "tracking_code") val trackingCode: String = "",
    @Json(name = "short_url") val shortUrl: String = "",
    @Json(name = "destination_url") val destinationUrl: String = "",
    // commission_percent / conversion_rate_pct are PERCENTAGES, display-only; decoded as Double only at
    // the DTO edge and never propagated into the money graph.
    @Json(name = "commission_percent") val commissionPercent: Double = 0.0,
    val status: String = "",
    @Json(name = "click_count") val clickCount: Long = 0,
    @Json(name = "unique_click_count") val uniqueClickCount: Long = 0,
    @Json(name = "conversion_count") val conversionCount: Long = 0,
    @Json(name = "revenue_cents") val revenueCents: Long = 0,
    @Json(name = "commission_earned_cents") val commissionEarnedCents: Long = 0,
    @Json(name = "conversion_rate_pct") val conversionRatePct: Double = 0.0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/**
 * Create-link request body. Mirrors reference AffiliateLinkCreateIn: target_type + target_id are always
 * sent; commission_percent / custom_code are optional (null -> omitted from the wire by Moshi).
 * commission_percent is a display-only percentage (0..100), never cents.
 */
@JsonClass(generateAdapter = true)
data class AffiliateLinkCreateRequest(
    @Json(name = "target_type") val targetType: String,
    @Json(name = "target_id") val targetId: String,
    @Json(name = "commission_percent") val commissionPercent: Int? = null,
    @Json(name = "custom_code") val customCode: String? = null,
)

/** DELETE ui/affiliates/links/{id} response: { "ok": true, "link_id": "..." }. */
@JsonClass(generateAdapter = true)
data class AffiliateDeleteDto(
    val ok: Boolean = false,
    @Json(name = "link_id") val linkId: String = "",
)
