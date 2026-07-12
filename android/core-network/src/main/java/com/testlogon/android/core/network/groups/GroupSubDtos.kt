package com.testlogon.android.core.network.groups

import com.squareup.moshi.Json

/**
 * AND-355 (sub-pages) - transport DTOs for the social-group SUB-PAGES: treasury, fundraising,
 * group advertising campaigns, and settings (group update).
 *
 * CODEGEN NOTE (identical to GroupDtos): core-network does NOT apply the Moshi KSP codegen plugin, so
 * these DTOs decode via the reflective KotlinJsonAdapterFactory on the shared Moshi. Every wire key is
 * pinned with an explicit @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required wire fields have NO default so a missing key
 * surfaces as a JsonDataException.
 *
 * WIRE CONTRACT (frontend-verified, ENVELOPE responses where noted):
 *   GET   ui/groups/{groupId}/treasury                          -> TreasuryBalanceDto
 *   GET   ui/groups/{groupId}/treasury/ledger                   -> {entries:[], cursor?, has_more}
 *   GET   ui/groups/{groupId}/treasury/contributors            -> {contributors:[], count}
 *   GET   ui/groups/fundraising/{groupId}/fundraisers           -> {fundraisers:[]}
 *   POST  ui/groups/fundraising/{groupId}/fundraisers           body GroupCreateFundraiserIn (admin)
 *   GET   ui/groups/fundraising/{groupId}/campaigns             -> {campaigns:[]}
 *   POST  ui/groups/fundraising/{groupId}/campaigns             body GroupCreateCampaignIn (admin)
 *   GET   ui/groups/fundraising/{groupId}/campaigns/{cid}/stats -> GroupCampaignStatsDto
 *   PATCH ui/groups/{groupId}                                   body GroupUpdateIn -> UserGroupDto
 */

// ---------------------------------------------------------------------------
// Treasury (GROUP-004)
// ---------------------------------------------------------------------------

data class TreasuryBalanceDto(
    @Json(name = "balance_cents") val balanceCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "total_contributed_cents") val totalContributedCents: Long? = null,
    @Json(name = "total_donated_cents") val totalDonatedCents: Long? = null,
    @Json(name = "total_spent_cents") val totalSpentCents: Long? = null,
    @Json(name = "fundraising_goal_cents") val fundraisingGoalCents: Long? = null,
)

data class TreasuryLedgerEntryDto(
    @Json(name = "entry_id") val entryId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "direction") val direction: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "actor_user_id") val actorUserId: String? = null,
    @Json(name = "actor_display_name") val actorDisplayName: String? = null,
    @Json(name = "reference_id") val referenceId: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

data class TreasuryLedgerResponse(
    @Json(name = "entries") val entries: List<TreasuryLedgerEntryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "has_more") val hasMore: Boolean? = null,
)

data class ContributorDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "total_contributed_cents") val totalContributedCents: Long? = null,
    @Json(name = "contribution_count") val contributionCount: Int? = null,
    @Json(name = "first_contributed_at") val firstContributedAt: Long? = null,
    @Json(name = "last_contributed_at") val lastContributedAt: Long? = null,
)

data class ContributorListResponse(
    @Json(name = "contributors") val contributors: List<ContributorDto> = emptyList(),
    @Json(name = "count") val count: Int? = null,
)

// ---------------------------------------------------------------------------
// Fundraising (GROUP-003)
// ---------------------------------------------------------------------------

data class GroupFundraiserDto(
    @Json(name = "fundraiser_id") val fundraiserId: String,
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "goal_cents") val goalCents: Long? = null,
    @Json(name = "raised_cents") val raisedCents: Long? = null,
    @Json(name = "donation_count") val donationCount: Int? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "cover_image_url") val coverImageUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "ends_at") val endsAt: Long? = null,
)

data class GroupFundraiserListResponse(
    @Json(name = "fundraisers") val fundraisers: List<GroupFundraiserDto> = emptyList(),
)

/** Body for POST ui/groups/fundraising/{groupId}/fundraisers (admin-gated at the service layer). */
data class GroupCreateFundraiserIn(
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "goal_cents") val goalCents: Long? = null,
    @Json(name = "cover_image_url") val coverImageUrl: String? = null,
    @Json(name = "ends_at") val endsAt: Long? = null,
)

// ---------------------------------------------------------------------------
// Group advertising campaigns (GROUP-003)
// ---------------------------------------------------------------------------

data class GroupCampaignDto(
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "name") val name: String,
    @Json(name = "status") val status: String? = null,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long? = null,
    @Json(name = "lifetime_budget_cents") val lifetimeBudgetCents: Long? = null,
    @Json(name = "spent_cents") val spentCents: Long? = null,
    @Json(name = "impressions") val impressions: Long? = null,
    @Json(name = "clicks") val clicks: Long? = null,
    @Json(name = "creative_text") val creativeText: String? = null,
    @Json(name = "creative_image_url") val creativeImageUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

data class GroupCampaignListResponse(
    @Json(name = "campaigns") val campaigns: List<GroupCampaignDto> = emptyList(),
)

data class GroupCampaignStatsDto(
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "impressions") val impressions: Long? = null,
    @Json(name = "clicks") val clicks: Long? = null,
    @Json(name = "ctr") val ctr: Double? = null,
    @Json(name = "spent_cents") val spentCents: Long? = null,
    @Json(name = "remaining_cents") val remainingCents: Long? = null,
    @Json(name = "daily_spent_cents") val dailySpentCents: Long? = null,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long? = null,
    @Json(name = "status") val status: String? = null,
)

/** Body for POST ui/groups/fundraising/{groupId}/campaigns (admin-gated at the service layer). */
data class GroupCreateCampaignIn(
    @Json(name = "name") val name: String,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long,
    @Json(name = "lifetime_budget_cents") val lifetimeBudgetCents: Long,
    @Json(name = "creative_text") val creativeText: String? = null,
    @Json(name = "creative_image_url") val creativeImageUrl: String? = null,
)

// ---------------------------------------------------------------------------
// Settings (group update)
// ---------------------------------------------------------------------------

/**
 * Body for PATCH ui/groups/{groupId} (admin-gated at the service layer). Only the non-null fields are
 * sent; nulls are omitted by the shared Moshi (serializeNulls is off on the production client).
 */
data class GroupUpdateIn(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "topic") val topic: String? = null,
)
