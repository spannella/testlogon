package com.testlogon.android.feature.adsbilling.data

import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.AdInvoiceLine
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.network.ads.AdAccountDto
import com.testlogon.android.core.network.ads.AdBillingEntryDto
import com.testlogon.android.core.network.ads.AdCampaignDto
import com.testlogon.android.core.network.ads.AdCampaignStatus
import com.testlogon.android.core.network.ads.AdDepositOut
import com.testlogon.android.core.network.ads.AdInvoiceCampaignLineDto
import com.testlogon.android.core.network.ads.AdInvoiceDto

/**
 * AND-367 - DTO -> domain mappers for the ads-account billing + deposit surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mappers live here in the feature, which depends on BOTH (mirrors AND-364 BoostMappers). All
 * *_cents stay Long (overflow-proof); created_at stays an epoch Long; nullable wire totals fold to 0 in the
 * non-null domain totals.
 */

/**
 * Maps the single-account DTO to the [AdAccountSummary] (balance + lifetime-spend live ON the account; there
 * is NO separate billing summary object). The account's `name` is used as the company-name label.
 */
fun AdAccountDto.toBillingSummary(): AdAccountSummary = AdAccountSummary(
    accountId = accountId,
    companyName = name,
    status = status.token,
    balanceCents = balanceCents,
    lifetimeSpendCents = lifetimeSpendCents,
)

/**
 * Maps one billing-ledger DTO row to [AdBillingEntry]. The AND-367 `entry_type` / `reason` keys win; the
 * older AND-363 `type` / `description` keys are a lenient fallback so an older-shaped server row still
 * displays.
 */
fun AdBillingEntryDto.toDomain(): AdBillingEntry = AdBillingEntry(
    entryType = entryType ?: type,
    amountCents = amountCents,
    state = state,
    reason = reason ?: description,
    createdAt = createdAt,
)

/** Maps a monthly-invoice DTO to [AdInvoice] (nullable totals fold to 0; lines mapped element-wise). */
fun AdInvoiceDto.toDomain(): AdInvoice = AdInvoice(
    month = month,
    totalChargesCents = totalChargesCents ?: 0L,
    totalDepositsCents = totalDepositsCents ?: 0L,
    entryCount = entryCount,
    campaigns = campaigns.map { it.toDomain() },
)

/** Maps one invoice campaign-line DTO to [AdInvoiceLine] (nullable counts / total fold to 0). */
fun AdInvoiceCampaignLineDto.toDomain(): AdInvoiceLine = AdInvoiceLine(
    campaignId = campaignId,
    impressions = impressions ?: 0L,
    clicks = clicks ?: 0L,
    conversions = conversions ?: 0L,
    totalCents = totalCents ?: 0L,
)

/** Maps the deposit response DTO to [DepositResult]. */
fun AdDepositOut.toDomain(): DepositResult = DepositResult(
    newBalanceCents = newBalanceCents,
)

/**
 * AND-369 - maps the account-list DTO to the [AdAccountSummary] domain row (the advertiser-accounts list
 * reuses the existing AND-367 summary type; the list row and the single-account GET share one wire shape).
 * The account's `name` is the company-name label and the status keeps its raw lowercase wire token.
 */
fun AdAccountDto.toAccountSummary(): AdAccountSummary = AdAccountSummary(
    accountId = accountId,
    companyName = name,
    status = status.token,
    balanceCents = balanceCents,
    lifetimeSpendCents = lifetimeSpendCents,
)

/**
 * AND-369 - maps one campaign DTO to the read-only [AdCampaign] domain. The raw wire status token is kept as
 * [AdCampaign.status] and parsed UNKNOWN-safely into [AdCampaign.statusEnum]; every *_cents stays an optional
 * Long and the timestamps stay optional epoch Longs.
 */
fun AdCampaignDto.toDomain(): AdCampaign = AdCampaign(
    campaignId = campaignId,
    accountId = accountId,
    name = name,
    status = status.token,
    statusEnum = status.toDomain(),
    budgetCents = budgetCents,
    dailyBudgetCents = dailyBudgetCents,
    spentTodayCents = spentTodayCents,
    lifetimeSpentCents = lifetimeSpentCents,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

/** AND-369 - translates the core-network campaign-status wire enum to the core-model domain enum. */
fun AdCampaignStatus.toDomain(): AdCampaignStatusDomain = when (this) {
    AdCampaignStatus.DRAFT -> AdCampaignStatusDomain.DRAFT
    AdCampaignStatus.ACTIVE -> AdCampaignStatusDomain.ACTIVE
    AdCampaignStatus.PAUSED -> AdCampaignStatusDomain.PAUSED
    AdCampaignStatus.COMPLETED -> AdCampaignStatusDomain.COMPLETED
    AdCampaignStatus.ARCHIVED -> AdCampaignStatusDomain.ARCHIVED
    AdCampaignStatus.UNKNOWN -> AdCampaignStatusDomain.UNKNOWN
}
