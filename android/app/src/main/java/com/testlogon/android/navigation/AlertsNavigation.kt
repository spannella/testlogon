package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.alerts.AlertsRoute

/** The alerts-inbox route (reached from the More hub). Mirrors the web /alerts page. */
data object AlertsDest {
    const val ROUTE = "alerts"
}

/** Registers the alerts-inbox destination in the authenticated graph. */
fun NavGraphBuilder.alertsDestination(navController: NavHostController) {
    composable(AlertsDest.ROUTE) {
        AlertsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            // MOD-D1: a moderation alert deep-links to the poster's content-review screen.
            onOpenModeration = { navController.navigate(ModerationReviewDest.ROUTE) },
            // MODX-15 (C6): a ban / content-removal alert deep-links to Appeals (a real next step).
            onOpenAppeals = { navController.navigate(AppealsDest.ROUTE) { launchSingleTop = true } },
            // ECOM-SELLER (G1): a shop_item_sold alert deep-links to that seller sale (ship group).
            onOpenSale = { shipGroupId ->
                navController.navigate(SellerSalesDest.build(shipGroupId)) { launchSingleTop = true }
            },
            // D4: a buyer shipment alert deep-links to the buyer order-tracking view (ship group).
            onOpenTracking = { shipGroupId ->
                navController.navigate(OrderTrackingDest.build(shipGroupId)) { launchSingleTop = true }
            },
            // PAY-51: a payout lifecycle alert (initiated/paid/failed/returned) deep-links to that
            // payout's statement/detail (action_url `/wallet/payouts/{payout_id}`).
            onOpenPayout = { payoutId ->
                navController.navigate(PayoutDetailDest.build(payoutId)) { launchSingleTop = true }
            },
            // SUB-E5: a subscription alert deep-links to Subscribers (creator) or manage-subscription.
            // The backend sets a per-recipient action_url; we route on its path, using the event to
            // disambiguate the bare "/subscriptions" path (creator-new-subscriber vs gift-recipient).
            onOpenSubscription = { event, actionUrl ->  // SUB-E5 / SUBX-50: (event, actionUrl)
                val path = actionUrl.substringBefore('?').trimEnd('/').lowercase()
                // SUBX-50: pull subscriptionId/creatorId off the action_url query so a
                // renewal-failed / cancel / removal / convert push lands on the SPECIFIC sub's
                // Manage/PAST_DUE recovery screen (SUBX-21/22), not the arg-less manage list.
                val query = actionUrl.substringAfter('?', "")
                val params = query.split('&').mapNotNull { kv ->
                    val i = kv.indexOf('=')
                    if (i <= 0) null else kv.substring(0, i) to Uri.decode(kv.substring(i + 1))
                }.toMap()
                val subscriptionId = params["subscriptionId"]?.takeIf { it.isNotBlank() }
                val creatorId = params["creatorId"]?.takeIf { it.isNotBlank() }
                val manageRoute = ManageSubscriptionDest.build(subscriptionId = subscriptionId, creatorId = creatorId)
                val dest = when {
                    // creator-side (new-subscriber / renewed / canceled / gifted) -> E4 Subscribers screen
                    path.endsWith("/subscribers") -> CreatorSubscribersDest.ROUTE
                    // subscriber-side (started / renewed / renewal-failed / expiring / expired / changed /
                    // removed / converted / gifter) -> the SPECIFIC sub's manage/recovery screen
                    path.endsWith("/manage") -> manageRoute
                    // bare "/subscriptions": a creator's new-subscriber alert -> Subscribers screen; a
                    // gift-recipient's alert (subscription_gifted) falls through to manage their new sub.
                    event == "subscription_started" || event == "subscription_new_subscriber" ->
                        CreatorSubscribersDest.ROUTE
                    else -> manageRoute
                }
                navController.navigate(dest) { launchSingleTop = true }
            },
        )
    }
}
