package com.testlogon.android.core.testing.ads

import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.AdInvoiceLine
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus

/**
 * AND-370 - SHARED, dependency-light domain fixtures for the ADS epic (E47: accounts / boost / sponsorship /
 * billing / analytics / viewmodels, AND-363..369) test suites.
 *
 * SCOPE (obey the core-testing dependency rule): core-testing depends on core-MODEL ONLY, so EVERYTHING here
 * references ONLY core-model ads / sponsorship domain types - the AND-367 [AdAccountSummary] / [AdBillingEntry]
 * / [AdInvoice] (+ [AdInvoiceLine]), the AND-369 [AdCampaign] (+ [AdCampaignStatusDomain]), the AND-368
 * [AdAnalyticsSummary] / [AdTimeSeriesPoint] / [AdBreakdownEntry], the AND-364 [ContentBoost] (+ [BoostStatus])
 * and the AND-365 / AND-366 [SponsorshipDeal] / [SponsorshipDealDetail] / [SponsorshipDealEvent]
 * (+ [SponsorshipDealStatus]). There are NO core-network DTOs and NO Moshi adapters here (those are
 * core-network scoped; a fixture needing a :app or core-network DTO type lives in that module's own test
 * source, not here). These are PURE in-memory domain builders, not JSON.
 *
 * WHY (anti-duplication): the existing E47 suites each hand-roll tiny throwaway domain samples. This
 * consolidates one realistic, reusable set covering the varied shapes the suites care about: a campaign list
 * spanning every [AdCampaignStatusDomain] (including UNKNOWN), an analytics summary carrying period-over-period
 * change deltas, a multi-point time series, a breakdown roster, a boost in an ACTIVE state AND a terminal one,
 * and a sponsorship-deal roster spanning all four client-side filter groups (Pending / Active / Completed /
 * Cancelled). It is ADDITIVE - it does NOT replace the narrow per-test builders any suite already uses.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object AdsFixtures {

    // ---- stable ids referenced across fixtures ----

    const val ACCOUNT_ID = "acct_fixture_1"
    const val CAMPAIGN_ID = "camp_fixture_1"
    const val BOOST_ID = "bst_fixture_1"
    const val DEAL_ID = "deal_fixture_1"

    const val ADVERTISER_SUB = "usr_advertiser"
    const val CREATOR_SUB = "usr_creator"

    // ---- AND-367: ads-account billing (summary / ledger / invoice) ----

    /** A sample ads-account billing summary (all amounts are flat *_cents Longs, implicit USD). */
    fun accountSummary(
        balanceCents: Long = 250_000L,
        lifetimeSpendCents: Long = 1_500_000L,
        status: String = "active",
    ): AdAccountSummary = AdAccountSummary(
        accountId = ACCOUNT_ID,
        companyName = "Acme Ads",
        status = status,
        balanceCents = balanceCents,
        lifetimeSpendCents = lifetimeSpendCents,
    )

    /** One billing-ledger row (signed [amountCents]; a deposit is positive, a charge negative). */
    fun billingEntry(
        entryType: String = "charge",
        amountCents: Long = -4_999L,
        state: String = "settled",
        reason: String? = "campaign spend",
        createdAt: Long? = 1_700_000_000L,
    ): AdBillingEntry = AdBillingEntry(
        entryType = entryType,
        amountCents = amountCents,
        state = state,
        reason = reason,
        createdAt = createdAt,
    )

    /** A mixed ledger carrying one deposit (positive) and one charge (negative). */
    fun billingLedger(): List<AdBillingEntry> = listOf(
        billingEntry(entryType = "deposit", amountCents = 100_000L, reason = "add funds", createdAt = 1_700_000_100L),
        billingEntry(entryType = "charge", amountCents = -4_999L, reason = "campaign spend", createdAt = 1_700_000_200L),
    )

    /** One per-campaign invoice line. */
    fun invoiceLine(
        campaignId: String = CAMPAIGN_ID,
        impressions: Long = 12_000L,
        clicks: Long = 240L,
        conversions: Long = 12L,
        totalCents: Long = 4_999L,
    ): AdInvoiceLine = AdInvoiceLine(
        campaignId = campaignId,
        impressions = impressions,
        clicks = clicks,
        conversions = conversions,
        totalCents = totalCents,
    )

    /** A monthly invoice with a two-line per-campaign breakdown. */
    fun invoice(month: String = "2026-05"): AdInvoice = AdInvoice(
        month = month,
        totalChargesCents = 9_998L,
        totalDepositsCents = 100_000L,
        entryCount = 2,
        campaigns = listOf(
            invoiceLine(campaignId = "camp_a", totalCents = 4_999L),
            invoiceLine(campaignId = "camp_b", totalCents = 4_999L),
        ),
    )

    // ---- AND-369: ad campaigns (varied status incl UNKNOWN) ----

    /**
     * One campaign whose RAW [status] string and typed [statusEnum] are kept consistent. [statusEnum] defaults
     * to [AdCampaignStatusDomain.ACTIVE]; pass [AdCampaignStatusDomain.UNKNOWN] for the forward-compat case.
     */
    fun campaign(
        campaignId: String = CAMPAIGN_ID,
        statusEnum: AdCampaignStatusDomain = AdCampaignStatusDomain.ACTIVE,
        status: String = statusEnum.name.lowercase(),
        name: String? = "Spring Launch",
    ): AdCampaign = AdCampaign(
        campaignId = campaignId,
        accountId = ACCOUNT_ID,
        name = name,
        status = status,
        statusEnum = statusEnum,
        budgetCents = 500_000L,
        dailyBudgetCents = 25_000L,
        spentTodayCents = 4_999L,
        lifetimeSpentCents = 120_000L,
        createdAt = 1_700_000_000L,
        updatedAt = 1_700_050_000L,
    )

    /**
     * A campaign list carrying one campaign of every [AdCampaignStatusDomain] (DRAFT / ACTIVE / PAUSED /
     * COMPLETED / ARCHIVED) PLUS one UNKNOWN row whose raw wire token is unrecognized, so a test can exercise
     * status grouping / sorting plus the forward-compat fallback off one list.
     */
    fun campaignList(): List<AdCampaign> = listOf(
        campaign(campaignId = "camp_draft", statusEnum = AdCampaignStatusDomain.DRAFT),
        campaign(campaignId = "camp_active", statusEnum = AdCampaignStatusDomain.ACTIVE),
        campaign(campaignId = "camp_paused", statusEnum = AdCampaignStatusDomain.PAUSED),
        campaign(campaignId = "camp_completed", statusEnum = AdCampaignStatusDomain.COMPLETED),
        campaign(campaignId = "camp_archived", statusEnum = AdCampaignStatusDomain.ARCHIVED),
        campaign(
            campaignId = "camp_unknown",
            statusEnum = AdCampaignStatusDomain.UNKNOWN,
            status = "teleporting",
        ),
    )

    // ---- AND-368: analytics (summary + change deltas / time series / breakdown) ----

    /**
     * A KPI summary carrying the non-null headline figures AND a full set of period-over-period change deltas
     * (a positive impressions trend and a negative spend trend) so a test can exercise both up and down arrows.
     */
    fun analyticsSummary(): AdAnalyticsSummary = AdAnalyticsSummary(
        impressions = 120_000L,
        clicks = 2_400L,
        spendCents = 480_000L,
        ctrPct = 2.0,
        cpaCents = 1_200L,
        effectiveCpmCents = 4_000L,
        completes = 1_800L,
        skips = 600L,
        completionRatePct = 75.0,
        impressionsChangePct = 12.5,
        clicksChangePct = 8.0,
        spendChangePct = -4.5,
        ctrChangePct = 1.0,
        cpaChangePct = -2.0,
        effectiveCpmChangePct = 0.0,
        completionRateChangePct = 3.25,
    )

    /** A three-point daily-bucketed time series (date-keyed). */
    fun timeSeries(): List<AdTimeSeriesPoint> = listOf(
        AdTimeSeriesPoint(date = "2026-05-13", impressions = 38_000L, clicks = 760L, spendCents = 152_000L),
        AdTimeSeriesPoint(date = "2026-05-14", impressions = 41_000L, clicks = 820L, spendCents = 164_000L),
        AdTimeSeriesPoint(date = "2026-05-15", impressions = 41_000L, clicks = 820L, spendCents = 164_000L),
    )

    /** A two-row dimension breakdown (one named via the joined campaign list, one without a name). */
    fun breakdown(): List<AdBreakdownEntry> = listOf(
        AdBreakdownEntry(
            key = "camp_a",
            campaignName = "Spring Launch",
            impressions = 80_000L,
            clicks = 1_600L,
            spendCents = 320_000L,
            ctrPct = 2.0,
        ),
        AdBreakdownEntry(
            key = "camp_b",
            campaignName = null,
            impressions = 40_000L,
            clicks = 800L,
            spendCents = 160_000L,
            ctrPct = 2.0,
        ),
    )

    // ---- AND-364: content boost (active + a terminal status) ----

    /** An ACTIVE boost (spend accrues, Cancel / refund offered). */
    fun activeBoost(boostId: String = BOOST_ID): ContentBoost = ContentBoost(
        boostId = boostId,
        status = "active",
        statusEnum = BoostStatus.ACTIVE,
        budgetCents = 500L,
        spentCents = 100L,
        remainingCents = 400L,
        durationSeconds = 3_600L,
        endsAt = 1_700_003_600L,
    )

    /** A TERMINAL (completed) boost - the poll must NOT re-arm against this. */
    fun completedBoost(boostId: String = BOOST_ID): ContentBoost =
        activeBoost(boostId).copy(
            status = "completed",
            statusEnum = BoostStatus.COMPLETED,
            spentCents = 500L,
            remainingCents = 0L,
        )

    // ---- AND-365 / AND-366: sponsorship deals (varied status across all four groups) + detail / events ----

    /**
     * One inbox row whose RAW [status] string and typed [statusEnum] are kept consistent. [statusEnum] defaults
     * to [SponsorshipDealStatus.PROPOSED] (an actionable, Pending-group deal).
     */
    fun deal(
        dealId: String = DEAL_ID,
        statusEnum: SponsorshipDealStatus = SponsorshipDealStatus.PROPOSED,
        status: String = statusEnum.name.lowercase(),
    ): SponsorshipDeal = SponsorshipDeal(
        dealId = dealId,
        advertiserSub = ADVERTISER_SUB,
        brief = "Promote the spring drop",
        status = status,
        statusEnum = statusEnum,
        compensationCents = 250_000L,
        deadline = "2026-07-01",
        createdAt = 1_700_000_000L,
    )

    /**
     * A deal roster carrying one deal from EACH of the four client-side filter groups: PROPOSED (Pending),
     * ACCEPTED (Active), COMPLETED (Completed) and CANCELLED (Cancelled), so a test can exercise the group
     * filter chips off one list.
     */
    fun dealInbox(): List<SponsorshipDeal> = listOf(
        deal(dealId = "deal_pending", statusEnum = SponsorshipDealStatus.PROPOSED),
        deal(dealId = "deal_active", statusEnum = SponsorshipDealStatus.ACCEPTED),
        deal(dealId = "deal_completed", statusEnum = SponsorshipDealStatus.COMPLETED),
        deal(dealId = "deal_cancelled", statusEnum = SponsorshipDealStatus.CANCELLED),
    )

    /** The FULL deal-detail subject (a superset of the inbox row), defaulting to an actionable PROPOSED state. */
    fun dealDetail(
        dealId: String = DEAL_ID,
        statusEnum: SponsorshipDealStatus = SponsorshipDealStatus.PROPOSED,
        status: String = statusEnum.name.lowercase(),
    ): SponsorshipDealDetail = SponsorshipDealDetail(
        dealId = dealId,
        advertiserSub = ADVERTISER_SUB,
        creatorSub = CREATOR_SUB,
        brief = "Promote the spring drop",
        status = status,
        statusEnum = statusEnum,
        compensationCents = 250_000L,
        deliverables = listOf("1 feed post", "3 stories"),
        deadline = "2026-07-01",
        cpmBonusCents = 5_000L,
        platformCommissionBps = 1_000,
        contentId = "content_1",
        hasPaymentDetails = true,
    )

    /** One negotiation / lifecycle event from the deal history. */
    fun dealEvent(
        eventId: String = "evt_fixture_1",
        eventType: String = "countered",
        actorSub: String = ADVERTISER_SUB,
        detailsText: String? = "Countered at 250000 cents",
        createdAt: Long? = 1_700_000_300L,
    ): SponsorshipDealEvent = SponsorshipDealEvent(
        eventId = eventId,
        eventType = eventType,
        actorSub = actorSub,
        detailsText = detailsText,
        createdAt = createdAt,
    )

    /** A two-event negotiation history (a counter followed by an acceptance). */
    fun dealEvents(): List<SponsorshipDealEvent> = listOf(
        dealEvent(eventId = "evt_1", eventType = "countered", actorSub = CREATOR_SUB),
        dealEvent(eventId = "evt_2", eventType = "accepted", actorSub = ADVERTISER_SUB, createdAt = 1_700_000_400L),
    )
}
