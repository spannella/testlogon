package com.testlogon.android.feature.ads.create.data

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV-108 / ADV3-5 (B6) - the "currently selected" advertiser account + campaign, set by the real create /
 * picker screens and consulted by the ads STUDIO editors (targeting / scheduling / optimization) so they open
 * against the CHOSEN campaign instead of the legacy first-of-first auto-resolve (AdsStudioCampaignResolver).
 *
 * PERSISTED (ADV3-5 / B6): the selection is now written to SharedPreferences so it SURVIVES a cold start. The
 * previous in-memory-only singleton lost the selection on process death, after which the studio editors
 * silently fell back to editing the "first campaign" - so a targeting/schedule/optimization edit could land on
 * the WRONG campaign with no picker or confirmation. Persisting the last explicit pick removes that silent
 * wrong-campaign edit. Thread-safe via an [AtomicReference] cache seeded from prefs at construction; writes
 * update the cache AND the prefs. Selecting an account clears a stale campaign that no longer belongs to it.
 */
@Singleton
class AdsStudioSelection @Inject constructor(
    @ApplicationContext context: Context,
) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val ref = AtomicReference(
        Selection(
            accountId = prefs.getString(KEY_ACCOUNT, null),
            campaignId = prefs.getString(KEY_CAMPAIGN, null),
        ),
    )

    /** Immutable snapshot of the current selection (either field null when unset). */
    data class Selection(val accountId: String? = null, val campaignId: String? = null)

    /** The current selection snapshot. */
    val current: Selection get() = ref.get()

    /** The selected campaign id, or null when nothing has been picked/created this session. */
    val selectedCampaignId: String? get() = ref.get().campaignId

    /** Records the chosen account, clearing any campaign that belonged to a different account. */
    fun selectAccount(accountId: String) {
        val updated = ref.updateAndGet { prior ->
            if (prior.accountId == accountId) prior.copy(accountId = accountId)
            else Selection(accountId = accountId, campaignId = null)
        }
        persist(updated)
    }

    /** Records the chosen campaign (and its owning account, when known). */
    fun selectCampaign(campaignId: String, accountId: String? = null) {
        val updated = ref.updateAndGet { prior ->
            prior.copy(
                accountId = accountId ?: prior.accountId,
                campaignId = campaignId,
            )
        }
        persist(updated)
    }

    private fun persist(selection: Selection) {
        prefs.edit()
            .putString(KEY_ACCOUNT, selection.accountId)
            .putString(KEY_CAMPAIGN, selection.campaignId)
            .apply()
    }

    private companion object {
        const val PREFS = "ads_studio_selection"
        const val KEY_ACCOUNT = "account_id"
        const val KEY_CAMPAIGN = "campaign_id"
    }
}
