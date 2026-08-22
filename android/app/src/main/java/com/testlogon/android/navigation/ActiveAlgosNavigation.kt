package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.markets.trade.ActiveAlgosRoute

/**
 * The Active-Algos monitor surface (client-side TWAP / Iceberg progress + pause/cancel), reached from
 * More -> Studio. Self-contained: observes the process-wide AlgoManager. Up / Back pops the back stack.
 */
data object ActiveAlgosDest {
    const val ROUTE = "trading/algos"
}

fun NavGraphBuilder.activeAlgosDestination(navController: NavHostController) {
    composable(ActiveAlgosDest.ROUTE) {
        ActiveAlgosRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
