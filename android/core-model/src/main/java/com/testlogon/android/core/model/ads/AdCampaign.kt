package com.testlogon.android.core.model.ads

/**
 * AND-369 - domain model for one advertising campaign under an account (the read-only campaigns list shown by
 * the AdsCampaignsViewModel). The advertiser-accounts list row reuses the existing AND-367 [AdAccountSummary]
 * (it already carries accountId / companyName / status / balanceCents / lifetimeSpendCents), so no new
 * account-list domain is added.
 *
 * core-model has NO Moshi dependency: this is a plain domain type. The transport DTO (core-network
 * AdCampaignDto) is mapped to this by the feature-layer mapper (core-model cannot see core-network's DTOs).
 *
 * STATUS: [status] is the RAW wire token (always present - the DTO defaults it) and [statusEnum] is the
 * UNKNOWN-safe parsed value (null only when the raw token was absent, which the DTO never lets happen).
 * MONEY: every monetary field is an optional flat *_cents [Long] (overflow-proof; null when the wire omits
 * it). Display currency is fixed to USD and formatted via core-model formatCents.
 * TIME: [createdAt] / [updatedAt] are optional EPOCH [Long]s (NOT ISO strings).
 */
data class AdCampaign(
    val campaignId: String,
    val accountId: String? = null,
    val name: String? = null,
    val status: String,
    val statusEnum: AdCampaignStatusDomain? = null,
    val budgetCents: Long? = null,
    val dailyBudgetCents: Long? = null,
    val spentTodayCents: Long? = null,
    val lifetimeSpentCents: Long? = null,
    val createdAt: Long? = null,
    val updatedAt: Long? = null,
)

/**
 * AND-369 - the domain-side lifecycle status of an ad campaign. Mirrors the core-network AdCampaignStatus
 * wire enum but lives in core-model (which has no core-network / Moshi dependency); the feature-layer mapper
 * translates the wire enum to this. [UNKNOWN] is the forward-safe fallback for any unrecognized token.
 */
enum class AdCampaignStatusDomain {
    DRAFT,
    ACTIVE,
    PAUSED,
    COMPLETED,
    ARCHIVED,
    UNKNOWN,
}
