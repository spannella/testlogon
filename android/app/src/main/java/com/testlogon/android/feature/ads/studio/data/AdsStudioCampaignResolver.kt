package com.testlogon.android.feature.ads.studio.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Shared account->campaign resolver for the ads STUDIO editors (targeting / scheduling / optimization).
 *
 * The web ads studio pages each take a concrete campaignId; the Android app has no campaign-picker nav yet,
 * so each studio editor opens against the caller's FIRST campaign under their FIRST ad account - exactly the
 * self-heal the read-only AdsCampaignsViewModel already does for the placeholder account id. This centralizes
 * that resolution (reusing the AND-367 [AdsBillingRepository] over the AND-363 AdsAccountsApi; no new
 * network code) so all three editors share one code path.
 *
 * Returns the resolved [AdCampaign] (so the screen can show which campaign it is editing), or a Failure /
 * NetworkError propagated from the underlying reads, or [NoCampaign] when the account has zero campaigns.
 */
@Singleton
class AdsStudioCampaignResolver @Inject constructor(
    private val billing: AdsBillingRepository,
    private val selection: AdsStudioSelection,
) {

    /** Sentinel error message surfaced when there is no account / no campaign to edit. */
    sealed interface Resolution {
        data class Found(val campaign: AdCampaign) : Resolution
        /** No ad account or no campaign under it - nothing to edit. */
        data object NoCampaign : Resolution
        /** A propagated transport / API failure (carries the original [ApiResult]). */
        data class Failed(val result: ApiResult<*>) : Resolution
    }

    /**
     * Resolves the first campaign of the caller's first ad account. If [accountId] / [campaignId] are already
     * concrete (non-null, non-placeholder) the resolution short-circuits to a campaign lookup by listing that
     * account's campaigns.
     */
    suspend fun resolveFirstCampaign(): Resolution {
        val accounts = when (val r = billing.listAccounts()) {
            is ApiResult.Success -> r.data
            else -> return Resolution.Failed(r)
        }
        // ADV-108: honor an explicit account/campaign chosen via the real create/picker screens
        // (AdsStudioSelection) before falling back to the legacy first-of-first auto-resolve.
        val picked = selection.current
        val accountId = picked.accountId?.takeIf { id -> accounts.any { it.accountId == id } }
            ?: accounts.firstOrNull()?.accountId
            ?: return Resolution.NoCampaign
        val campaigns = when (val r = billing.getCampaigns(accountId)) {
            is ApiResult.Success -> r.data
            else -> return Resolution.Failed(r)
        }
        if (campaigns.isEmpty()) return Resolution.NoCampaign
        val campaign = campaigns.firstOrNull { it.campaignId == picked.campaignId }
            ?: campaigns.first()
        return Resolution.Found(campaign)
    }
}
