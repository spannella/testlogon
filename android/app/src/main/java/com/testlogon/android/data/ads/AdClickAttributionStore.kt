package com.testlogon.android.data.ads

import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV-405 — session-scoped last-click ad-attribution handle.
 *
 * When a viewer taps a sponsored unit (the newsfeed Sponsored card / its CTA, ADV-106), the per-serve
 * `ad_click_id` minted by serve_ad (ADV-103, carried on
 * [com.testlogon.android.data.feed.SponsoredInfo.adClickId]) is recorded here as the current
 * last-click. If the viewer then completes a conversion within the same process session — SUBSCRIBE
 * (ADV-402), POST-UNLOCK (ADV-404) or CART CHECKOUT (ADV-403) — the stored id is attached to that
 * call so the ADV-B4 backend attribution service (`ad_attribution.attribute_conversion`) can join the
 * purchase back to the AdClicks row, mark it converted and charge the campaign's CPA bid.
 *
 * Semantics: LAST-CLICK — a newer sponsored tap overwrites the prior handle. Process-scoped (a plain
 * in-memory singleton). The backend independently enforces the strict 7-day AdClicks window, the
 * strict same-viewer / unexpired / unconverted classification and one-conversion-per-click
 * idempotency, so the id is deliberately NOT consumed on read: a stale / foreign / already-converted
 * id is a hard server-side no-op, and re-sending the same id across calls cannot double-charge.
 */
@Singleton
class AdClickAttributionStore @Inject constructor() {

    private val lastClick = AtomicReference<String?>(null)

    /** Record the most-recent sponsored-CTA click. Blank/null ids are ignored (nothing to attribute). */
    fun record(adClickId: String?) {
        val id = adClickId?.takeIf { it.isNotBlank() } ?: return
        lastClick.set(id)
    }

    /**
     * The current last-click `ad_click_id` to attach to a conversion, or null if the viewer has not
     * tapped a sponsored unit this session. Non-consuming (see class doc: the backend is idempotent).
     */
    fun peek(): String? = lastClick.get()

    /** Drop the stored handle (e.g. on logout / account switch). */
    fun clear() {
        lastClick.set(null)
    }
}
