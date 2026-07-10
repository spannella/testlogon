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
        )
    }
}
