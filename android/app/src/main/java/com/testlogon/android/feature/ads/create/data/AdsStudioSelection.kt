package com.testlogon.android.feature.ads.create.data

import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV-108 - the app-process "currently selected" advertiser account + campaign, set by the real create /
 * picker screens and consulted by the ads STUDIO editors (targeting / scheduling / optimization) so they open
 * against the CHOSEN campaign instead of the legacy first-of-first auto-resolve (AdsStudioCampaignResolver).
 *
 * In-memory ONLY (a process-scoped @Singleton; no persistence) - a fresh cold start with no selection falls
 * back to the auto-resolve, so existing More-hub stub entries keep working. Thread-safe via [AtomicReference]
 * (writes come from VM coroutines, reads from the resolver on IO). Selecting an account clears a stale campaign
 * that no longer belongs to it.
 */
@Singleton
class AdsStudioSelection @Inject constructor() {

    private val ref = AtomicReference(Selection())

    /** Immutable snapshot of the current selection (either field null when unset). */
    data class Selection(val accountId: String? = null, val campaignId: String? = null)

    /** The current selection snapshot. */
    val current: Selection get() = ref.get()

    /** The selected campaign id, or null when nothing has been picked/created this session. */
    val selectedCampaignId: String? get() = ref.get().campaignId

    /** Records the chosen account, clearing any campaign that belonged to a different account. */
    fun selectAccount(accountId: String) {
        ref.getAndUpdate { prior ->
            if (prior.accountId == accountId) prior.copy(accountId = accountId)
            else Selection(accountId = accountId, campaignId = null)
        }
    }

    /** Records the chosen campaign (and its owning account, when known). */
    fun selectCampaign(campaignId: String, accountId: String? = null) {
        ref.getAndUpdate { prior ->
            prior.copy(
                accountId = accountId ?: prior.accountId,
                campaignId = campaignId,
            )
        }
    }
}
