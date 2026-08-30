package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.tradingdocs.TradingDocsRoute

/**
 * FE-170 — the Trading Documents list route (statements / 1099s / trade confirmations), reached from the
 * file-manager entry point. Downloads open in a Custom Tab; degrades to an empty state on a 404. This
 * route lives in the files feature graph (NOT the More catalog), so it does not touch MoreCatalog /
 * RouteRegistry.
 */
data object TradingDocsDest {
    const val ROUTE = "files/trading-documents"
}

/** FE-170 — registers the Trading Documents list destination. */
fun NavGraphBuilder.tradingDocsDestination(navController: NavHostController) {
    composable(TradingDocsDest.ROUTE) {
        TradingDocsRoute(onBack = { navController.popBackStack() })
    }
}
