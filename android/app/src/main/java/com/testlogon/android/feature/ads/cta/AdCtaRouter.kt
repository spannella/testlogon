package com.testlogon.android.feature.ads.cta

import androidx.navigation.NavHostController
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.ads.CtaType
import com.testlogon.android.navigation.CartDest
import com.testlogon.android.navigation.CatalogDest
import com.testlogon.android.navigation.ProductDetailDest
import com.testlogon.android.navigation.PublicProfileDest
import com.testlogon.android.navigation.SubscriptionTiersDest

/**
 * ADV2-208 (F2) — the resolved in-app destination for a tapped CTA. Pure data so [AdCtaRouter] mapping
 * is JVM-unit-testable; the actual navigation is [navigateCta] (needs the NavController).
 */
sealed interface CtaDestination {
    /** Ecommerce product detail. product target_id convention is "categoryId/itemId". */
    data class Product(val categoryId: String, val itemId: String) : CtaDestination
    /** Fallback when a product CTA has no resolvable "categoryId/itemId" target. */
    data object Catalog : CtaDestination
    /** The cart / checkout (buy that carries the stashed ad_click_id → CPA on purchase). */
    data object Cart : CtaDestination
    /** Subscription tiers for a creator (subscribe this creator / subscribe another account). */
    data class Subscriptions(val creatorId: String) : CtaDestination
    /** A creator's public profile (the universal tip / subscribe surface). */
    data class Profile(val identifier: String) : CtaDestination
    /** Deep-link to the tip flow for [creatorId] — NO advertiser charge (E2 locked default). */
    data class Tip(val creatorId: String) : CtaDestination
    /** Nothing to route (missing target). */
    data object None : CtaDestination
}

/**
 * ADV2-208 (F2) — the SHARED, reusable mapping from a structured [CtaAction] to an in-app destination,
 * used identically by the VOD detail player, the broadcast viewer and the newsfeed sponsored card:
 *
 *  - buy_product / view_product  -> ecommerce Product detail (add-to-cart / buy → checkout carries the
 *                                   stashed ad_click_id so the existing cart CPA attribution fires);
 *                                   falls back to the Catalog when no "categoryId/itemId" target.
 *  - subscribe                   -> the subscription tiers for THIS creator (the placement content
 *                                   owner); falls back to the CTA target_id if the owner is unknown
 *                                   (e.g. the broadcast surface, which doesn't carry it client-side).
 *  - subscribe_other             -> the subscription tiers for ANOTHER account (the CTA target_id).
 *  - tip                         -> the tip flow for the content owner (no advertiser charge).
 *
 * [contentOwnerId] is the placement creator when the surface knows it (VOD = video owner, feed =
 * sponsored creatorId); pass "" when unknown (broadcast) so the mapping falls back to the target_id.
 */
object AdCtaRouter {

    fun destinationFor(action: CtaAction, contentOwnerId: String): CtaDestination = when (action.ctaType) {
        CtaType.BUY_PRODUCT, CtaType.VIEW_PRODUCT -> product(action.targetId)
        CtaType.SUBSCRIBE -> {
            val creator = contentOwnerId.ifBlank { action.targetId }
            if (creator.isBlank()) CtaDestination.None else CtaDestination.Subscriptions(creator)
        }
        CtaType.SUBSCRIBE_OTHER -> {
            val creator = action.targetId.ifBlank { contentOwnerId }
            if (creator.isBlank()) CtaDestination.None else CtaDestination.Subscriptions(creator)
        }
        CtaType.TIP -> {
            val creator = contentOwnerId.ifBlank { action.targetId }
            if (creator.isBlank()) CtaDestination.None else CtaDestination.Tip(creator)
        }
    }

    /** product target_id is "categoryId/itemId" (slash-joined); anything else → the browse Catalog. */
    private fun product(targetId: String): CtaDestination {
        val parts = targetId.split("/").map { it.trim() }.filter { it.isNotBlank() }
        return if (parts.size >= 2) CtaDestination.Product(parts[0], parts[1]) else CtaDestination.Catalog
    }
}

/**
 * ADV2-208 — navigate a resolved [CtaDestination] on the single-Activity NavHost using the existing
 * typed route builders. [onTip] deep-links to the tip flow (the VOD screen opens its in-screen tip
 * sheet; other surfaces default to the creator's profile, where a tip affordance lives). Reuses
 * existing product / cart / subscription / profile destinations — no new routes.
 */
fun NavHostController.navigateCta(
    dest: CtaDestination,
    onTip: (creatorId: String) -> Unit = { navigate(PublicProfileDest.build(it)) { launchSingleTop = true } },
) {
    when (dest) {
        is CtaDestination.Product ->
            navigate(ProductDetailDest.build(dest.categoryId, dest.itemId)) { launchSingleTop = true }
        CtaDestination.Catalog -> navigate(CatalogDest.ROUTE) { launchSingleTop = true }
        CtaDestination.Cart -> navigate(CartDest.ROUTE) { launchSingleTop = true }
        is CtaDestination.Subscriptions ->
            navigate(SubscriptionTiersDest.build(dest.creatorId)) { launchSingleTop = true }
        is CtaDestination.Profile -> navigate(PublicProfileDest.build(dest.identifier)) { launchSingleTop = true }
        is CtaDestination.Tip -> onTip(dest.creatorId)
        CtaDestination.None -> Unit
    }
}
