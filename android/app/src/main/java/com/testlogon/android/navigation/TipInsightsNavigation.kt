package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.tipinsights.TipInsightsRoute

/** TIPX-D3/D4 — the ledger-backed tip insights route (top supporters + received/sent history). */
data object TipInsightsDest {
    const val ROUTE = "tip-insights"
}

/** TIPX-D3/D4 — registers the tip insights destination. */
fun NavGraphBuilder.tipInsightsDestinations(navController: NavHostController) {
    composable(TipInsightsDest.ROUTE) {
        TipInsightsRoute(onBack = { navController.popBackStack() })
    }
}
