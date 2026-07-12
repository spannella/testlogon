package com.testlogon.android.data.ads

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV2-208 (F2) — the SHARED, reusable money-side handler for a CTA tap, used identically by the VOD
 * detail player, the broadcast viewer (pre/mid-roll) and the newsfeed sponsored card. Keeps the
 * charge + attribution rules in ONE place so every surface behaves the same:
 *
 *  - NON-tip CTA (buy_product / view_product / subscribe / subscribe_other): fire the CPC click via
 *    [AdTrackRepository.clickCta] (backend charges CPC, funds-guarded, idempotent per
 *    {ad_click_id}#cta#{cta_type}) AND stash the per-serve `ad_click_id` in
 *    [AdClickAttributionStore] so a resulting purchase / subscribe attributes the CPA via the
 *    already-shipped last-click conversion path (cart checkout / subscribe / unlock read it back).
 *  - TIP CTA: NO advertiser charge (E2 locked default) — the viewer tips the creator as normal
 *    creator-earnings. We deliberately do NOT fire the CPC click and do NOT stash the id (no
 *    advertiser conversion on a tip). The caller still deep-links to the tip flow.
 *
 * Navigation is the caller's concern (see [com.testlogon.android.feature.ads.AdCtaRouter]); this only
 * owns the ledger side. Fire-and-forget: a failed beacon never blocks the tap.
 */
@Singleton
class AdCtaClicker @Inject constructor(
    private val adTracker: AdTrackRepository,
    private val attribution: AdClickAttributionStore,
) {
    /**
     * Handle the ledger side of a CTA tap. [adClickId] is the per-serve id minted by serve_ad and
     * carried on the served unit; blank ids are a no-op (nothing to charge / attribute).
     */
    fun onTap(scope: CoroutineScope, adClickId: String?, action: CtaAction) {
        if (action.isTip) return // tip: no advertiser charge, no conversion stash.
        val id = adClickId?.takeIf { it.isNotBlank() } ?: return
        // Stash first so a purchase/subscribe started immediately from the CTA target attributes CPA.
        attribution.record(id)
        scope.launch { adTracker.clickCta(id, action) }
    }
}
