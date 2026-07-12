package com.testlogon.android.navigation

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
            // ECOM-SELLER (G1): a shop_item_sold alert deep-links to that seller sale (ship group).
            onOpenSale = { shipGroupId ->
                navController.navigate(SellerSalesDest.build(shipGroupId)) { launchSingleTop = true }
            },
            // D4: a buyer shipment alert deep-links to the buyer order-tracking view (ship group).
            onOpenTracking = { shipGroupId ->
                navController.navigate(OrderTrackingDest.build(shipGroupId)) { launchSingleTop = true }
            },
            // SUB-E5: a subscription alert deep-links to Subscribers (creator) or manage-subscription.
            // The backend sets a per-recipient action_url; we route on its path, using the event to
            // disambiguate the bare "/subscriptions" path (creator-new-subscriber vs gift-recipient).
            onOpenSubscription = { event, actionUrl ->  // SUB-E5: (event, actionUrl)
                val path = actionUrl.substringBefore('?').trimEnd('/').lowercase()
                val dest = when {
                    // creator-side (new-subscriber / renewed / canceled / gifted) -> E4 Subscribers screen
                    path.endsWith("/subscribers") -> CreatorSubscribersDest.ROUTE
                    // subscriber-side (started / renewed / renewal-failed / expiring / expired / gifter) -> manage
                    path.endsWith("/manage") -> ManageSubscriptionDest.ROUTE
                    // bare "/subscriptions": a creator's new-subscriber alert -> Subscribers screen; a
                    // gift-recipient's alert (subscription_gifted) falls through to manage their new sub.
                    event == "subscription_started" || event == "subscription_new_subscriber" ->
                        CreatorSubscribersDest.ROUTE
                    else -> ManageSubscriptionDest.ROUTE
                }
                navController.navigate(dest) { launchSingleTop = true }
            },
        )
    }
}
