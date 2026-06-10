package com.testlogon.android.data.messaging.mass

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-160 — Retrofit interface for the mass-messages (broadcast campaign) surface.
 *
 * Kept SEPARATE from [com.testlogon.android.data.messaging.MessagingApi] on purpose (per the AND-160
 * gotchas): a dedicated interface keeps the large MessagingApi + its hand-written test FakeApi
 * untouched. Paths are relative (no leading slash) so they resolve against the shared Retrofit base
 * URL; cookies, Authorization and `X-CSRF-Token` are attached by the core-network interceptor chain.
 * All methods are `suspend`; non-2xx surfaces as retrofit2.HttpException.
 *
 * Endpoints verified against reference/openapi.index.txt (lines 395, 396, 398) and
 * reference/openapi.pretty.json (components.schemas.MassMessage*):
 *  - list   GET  messaging/mass-messages?limit=&cursor=&status=&mode=  -> 200 MassMessageCampaignListResponse
 *  - create POST messaging/mass-messages                               -> 201 MassMessageCreateCampaignResponse
 *  - cancel POST messaging/mass-messages/{campaign_id}/cancel          -> 200 MassMessageCancelCampaignResponse
 *
 * The detail/destinations GET (op get_mass_message_campaign_*) is intentionally OUT OF SCOPE for AND-160.
 * All timestamps are integer Unix epoch SECONDS (NOT ISO-8601). The list is the ONLY paged endpoint
 * here (cursor pagination via next_cursor).
 */
interface MassMessageApi {

    /** List the creator's campaigns, newest first. Cursor pagination via next_cursor. Idempotent GET. */
    @GET("messaging/mass-messages")
    suspend fun listCampaigns(
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
        @Query("status") status: String? = null,
        @Query("mode") mode: String? = null,
    ): MassMessageCampaignListResponseDto

    /**
     * Create a campaign. Body = MassMessageCreateCampaignRequest (required: conversation_ids[1..100],
     * content{kind:"text", text[1..4000]}); optional mode/send_at/idempotency_key. Returns HTTP 201.
     * Non-idempotent at the HTTP layer but carries a client idempotency_key, so a user-initiated retry
     * with the SAME key is duplicate-safe server-side. Not auto-retried.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/mass-messages")
    suspend fun createCampaign(
        @Body body: MassMessageCreateCampaignRequestDto,
    ): MassMessageCreateCampaignResponseDto

    /**
     * Cancel a non-terminal campaign (no body). Returns HTTP 200 MassMessageCancelCampaignResponse.
     * Naturally idempotent server-side; not auto-retried.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/mass-messages/{campaign_id}/cancel")
    suspend fun cancelCampaign(
        @Path("campaign_id") campaignId: String,
    ): MassMessageCancelCampaignResponseDto

    companion object {
        /** Page size for the campaign list (server default unspecified; client choice). */
        const val DEFAULT_LIMIT = 20
    }
}

// ---- Wire DTOs (names mirror components.schemas.MassMessage*; epoch-SECONDS Longs) ----

/** MassMessageCampaignCounters = {total, queued, sent, failed, cancelled} (all int >= 0, default 0). */
@JsonClass(generateAdapter = true)
data class MassMessageCountersDto(
    val total: Int = 0,
    val queued: Int = 0,
    val sent: Int = 0,
    val failed: Int = 0,
    val cancelled: Int = 0,
)

/**
 * MassMessageCampaignSummary — list item. NO message text, NO audience, NO recipient_count.
 * Required: campaign_id, mode, status, created_at, updated_at. send_at is nullable epoch-seconds.
 */
@JsonClass(generateAdapter = true)
data class MassMessageCampaignSummaryDto(
    @Json(name = "campaign_id") val campaignId: String,
    val mode: String = "immediate",
    val status: String = "pending",
    @Json(name = "send_at") val sendAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    val counters: MassMessageCountersDto = MassMessageCountersDto(),
)

/** MassMessageCampaignListResponse = {items, next_cursor?}. */
@JsonClass(generateAdapter = true)
data class MassMessageCampaignListResponseDto(
    val items: List<MassMessageCampaignSummaryDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** MassMessageContentPayload = {kind:"text", text[1..4000]}. */
@JsonClass(generateAdapter = true)
data class MassMessageContentPayloadDto(
    val kind: String = "text",
    val text: String,
)

/**
 * MassMessageCreateCampaignRequest. Required: conversation_ids, content. There is NO audience,
 * price/PPV, or media field on this endpoint.
 */
@JsonClass(generateAdapter = true)
data class MassMessageCreateCampaignRequestDto(
    @Json(name = "conversation_ids") val conversationIds: List<String>,
    val content: MassMessageContentPayloadDto,
    val mode: String = "immediate",
    @Json(name = "send_at") val sendAt: Long? = null,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** MassMessageRejectedDestination = {conversation_id, reason}. */
@JsonClass(generateAdapter = true)
data class MassMessageRejectedDestinationDto(
    @Json(name = "conversation_id") val conversationId: String,
    val reason: String,
)

/**
 * MassMessageCreateCampaignResponse (HTTP 201). Required: campaign_id, mode, status, accepted_count,
 * created_at, updated_at. `rejected[]` carries non-fatal dropped destinations.
 */
@JsonClass(generateAdapter = true)
data class MassMessageCreateCampaignResponseDto(
    @Json(name = "campaign_id") val campaignId: String,
    val mode: String = "immediate",
    val status: String = "pending",
    @Json(name = "accepted_count") val acceptedCount: Int = 0,
    @Json(name = "accepted_conversation_ids") val acceptedConversationIds: List<String> = emptyList(),
    val rejected: List<MassMessageRejectedDestinationDto> = emptyList(),
    @Json(name = "send_at") val sendAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    val counters: MassMessageCountersDto = MassMessageCountersDto(),
)

/**
 * MassMessageCancelCampaignResponse (HTTP 200). Required: campaign_id, status, cancelled_destinations,
 * updated_at. Does NOT echo the full summary (no mode/created_at).
 */
@JsonClass(generateAdapter = true)
data class MassMessageCancelCampaignResponseDto(
    @Json(name = "campaign_id") val campaignId: String,
    val status: String = "cancelled",
    @Json(name = "cancelled_destinations") val cancelledDestinations: Int = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    val counters: MassMessageCountersDto = MassMessageCountersDto(),
)
