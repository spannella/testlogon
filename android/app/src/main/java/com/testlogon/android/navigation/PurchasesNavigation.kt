package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.purchases.PurchaseHistoryRoute

/** AND-219 — the purchase-history list + search screen. */
data object PurchaseHistoryDest {
    const val ROUTE = "purchases/history"
}

/**
 * AND-219 — registers the purchase-history list/search screen. A row tap opens the AND-220 order detail
 * via [TrackingDest] (the order-detail host that embeds the AND-215 tracking section), carrying the txn id.
 */
fun NavGraphBuilder.purchaseHistoryDestination(navController: NavHostController) {
    composable(PurchaseHistoryDest.ROUTE) {
        PurchaseHistoryRoute(
            onPurchaseClick = { txnId ->
                navController.navigate(TrackingDest.build(txnId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
