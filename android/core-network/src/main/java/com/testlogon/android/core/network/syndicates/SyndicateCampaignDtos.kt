package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.Json

/**
 * Transport DTOs for the syndicate-advertising campaign DETAIL surface (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId). Backend: app/routers/syndicate_advertising.py,
 * prefix /ui/syndicates/advertising.
 *
 * CODEGEN NOTE: reflective KotlinJsonAdapterFactory - every wire key pinned with @Json(name = ...);
 * @JsonClass(generateAdapter=true) OMITTED.
 *
 * TIME: created_at / updated_at are EPOCH SECONDS (Long). MONEY: *_cents are Int. `creative` / `targeting`
 * / `stats_summary` are free-form objects on the wire (typed as nullable string maps for display).
 */

/** One syndicate ad campaign (GET .../campaigns/{cid} and the list). */
data class SyndicateCampaignOut(
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "syndicate_id") val syndicateId: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "budget_cents") val budgetCents: Int = 0,
    @Json(name = "spent_cents") val spentCents: Int = 0,
    @Json(name = "remaining_cents") val remainingCents: Int = 0,
    @Json(name = "creative") val creative: Map<String, String?>? = null,
    @Json(name = "start_date") val startDate: String? = null,
    @Json(name = "end_date") val endDate: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** One day of campaign analytics (analytics.daily[]). */
data class SyndicateCampaignDailyStatsOut(
    @Json(name = "date") val date: String,
    @Json(name = "impressions") val impressions: Int = 0,
    @Json(name = "clicks") val clicks: Int = 0,
    @Json(name = "spend_cents") val spendCents: Int = 0,
    @Json(name = "unique_viewers") val uniqueViewers: Int = 0,
)

/** Campaign analytics envelope (GET .../campaigns/{cid}/analytics): daily series + free-form totals. */
data class SyndicateCampaignAnalyticsOut(
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "daily") val daily: List<SyndicateCampaignDailyStatsOut> = emptyList(),
    @Json(name = "totals") val totals: Map<String, Double?>? = null,
)

/** Request body for POST .../campaigns/{cid}/status. */
data class SyndicateCampaignStatusUpdateIn(
    @Json(name = "status") val status: String,
)

/** Request body for POST .../campaigns/{cid}/add-budget. */
data class SyndicateCampaignBudgetAddIn(
    @Json(name = "additional_cents") val additionalCents: Int,
)
