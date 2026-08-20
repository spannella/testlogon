package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.reports.ReportsRoute

/**
 * The read-only Export & Reporting surface, reached from the More -> Wallet hub (near PnL). Picks a
 * period (24h/7d/30d/All), shows headline stats over the period-scoped fills, and exports trade
 * history / PnL summary / account statement as CSV via the system share sheet. No money movement.
 */
data object ReportsDest {
    const val ROUTE = "reports"
}

/** Registers the Export & Reporting screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.reportsDestination(navController: NavHostController) {
    composable(ReportsDest.ROUTE) {
        ReportsRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
