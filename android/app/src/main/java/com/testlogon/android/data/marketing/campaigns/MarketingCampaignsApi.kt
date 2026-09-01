package com.testlogon.android.data.marketing.campaigns

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the OFBiz Marketing CAMPAIGNS surface (MKT).
 *
 * Mirrors frontend/src/api/endpoints/marketing.ts (BASE /ui/marketing, router
 * app/routers/marketing_campaigns.py). Reads (`require_ui_session`) are ungated so they answer even
 * when the MARKETING_CAMPAIGNS_ENABLED flag is off (empty results). Mutations call `_require_enabled()`
 * → 404 while the flag is off, so the repo degrades-on-404 (reads honest-empty, writes error).
 *
 * This is DISTINCT from [com.testlogon.android.data.marketing.MarketingApi], which targets the
 * `/ui/agents/marketing` marketing *content agent* (blog/social content). Do not conflate.
 *
 * Timestamps are epoch-SECONDS (Long). Session cookies / Bearer / X-CSRF-Token are attached by
 * interceptors; paths are relative (base URL carries the trailing slash).
 */
interface MarketingCampaignsApi {

    // ---- Campaigns ----

    @GET("ui/marketing/campaigns")
    suspend fun listCampaigns(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): CampaignListRespDto

    @GET("ui/marketing/campaigns/{campaignId}")
    suspend fun getCampaign(@Path("campaignId") campaignId: String): MarketingCampaignDto

    @POST("ui/marketing/campaigns")
    suspend fun createCampaign(@Body body: MarketingCampaignCreateInDto): MarketingCampaignDto

    @PATCH("ui/marketing/campaigns/{campaignId}")
    suspend fun updateCampaign(
        @Path("campaignId") campaignId: String,
        @Body body: MarketingCampaignUpdateInDto,
    ): MarketingCampaignDto

    @POST("ui/marketing/campaigns/{campaignId}/transition")
    suspend fun transitionCampaign(
        @Path("campaignId") campaignId: String,
        @Body body: CampaignTransitionInDto,
    ): MarketingCampaignDto

    @POST("ui/marketing/campaigns/{campaignId}/send")
    suspend fun sendCampaign(
        @Path("campaignId") campaignId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): CampaignSendRespDto

    // ---- Contact lists ----

    @GET("ui/marketing/lists")
    suspend fun listContactLists(): List<ContactListDto>

    @POST("ui/marketing/lists")
    suspend fun createContactList(@Body body: ContactListCreateInDto): ContactListDto

    @GET("ui/marketing/lists/{listId}/members")
    suspend fun listContactListMembers(
        @Path("listId") listId: String,
        @Query("include_suppressed") includeSuppressed: Boolean = true,
    ): List<ContactListMemberDto>

    // ---- Segments ----

    @GET("ui/marketing/segments")
    suspend fun listSegments(): List<PartySegmentDto>

    @GET("ui/marketing/segments/{segmentId}")
    suspend fun getSegment(@Path("segmentId") segmentId: String): PartySegmentDto
}

// ---- Campaign DTOs ----

@JsonClass(generateAdapter = true)
data class MarketingCampaignDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "owner_id") val ownerId: String = "",
    val name: String = "",
    val objective: String = "",
    val status: String = "",
    @Json(name = "budget_cents") val budgetCents: Long = 0,
    @Json(name = "ad_campaign_id") val adCampaignId: String? = null,
    @Json(name = "promo_code_ids") val promoCodeIds: List<String>? = null,
    @Json(name = "contact_list_ids") val contactListIds: List<String>? = null,
    @Json(name = "segment_ids") val segmentIds: List<String>? = null,
    @Json(name = "tracking_code") val trackingCode: String? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CampaignListRespDto(
    val campaigns: List<MarketingCampaignDto> = emptyList(),
    val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class MarketingCampaignCreateInDto(
    val name: String,
    val objective: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "contact_list_ids") val contactListIds: List<String>? = null,
    @Json(name = "segment_ids") val segmentIds: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class MarketingCampaignUpdateInDto(
    val name: String? = null,
    val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long? = null,
    val status: String? = null,
)

@JsonClass(generateAdapter = true)
data class CampaignTransitionInDto(
    @Json(name = "target_status") val targetStatus: String,
)

@JsonClass(generateAdapter = true)
data class CampaignSendRespDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "sent_count") val sentCount: Int = 0,
    @Json(name = "skipped_count") val skippedCount: Int = 0,
    @Json(name = "snapshot_ts") val snapshotTs: Long = 0,
)

// ---- Contact-list DTOs ----

@JsonClass(generateAdapter = true)
data class ContactListDto(
    @Json(name = "list_id") val listId: String = "",
    @Json(name = "owner_id") val ownerId: String = "",
    val name: String = "",
    val description: String? = null,
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ContactListCreateInDto(
    val name: String,
    val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class ContactListMemberDto(
    @Json(name = "list_id") val listId: String = "",
    @Json(name = "party_id") val partyId: String = "",
    @Json(name = "joined_at") val joinedAt: Long? = null,
    val suppressed: Boolean? = null,
    @Json(name = "display_name") val displayName: String? = null,
)

// ---- Segment DTOs ----

@JsonClass(generateAdapter = true)
data class SegmentPredicateDto(
    val attribute: String = "",
    val operator: String = "",
    val value: Any? = null,
)

@JsonClass(generateAdapter = true)
data class PartySegmentDto(
    @Json(name = "segment_id") val segmentId: String = "",
    @Json(name = "owner_id") val ownerId: String = "",
    val name: String = "",
    val description: String? = null,
    val predicates: List<SegmentPredicateDto>? = null,
    @Json(name = "candidate_source") val candidateSource: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)
