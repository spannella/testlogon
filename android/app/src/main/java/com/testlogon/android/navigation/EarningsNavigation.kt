package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.earnings.EarningsRoute
import com.testlogon.android.feature.earnings.EarningsViewModel
import com.testlogon.android.feature.earnings.percontent.PerContentRevenueRoute

/** AND-252 — the earnings dashboard route; optional `range` arg deep-links to a preset range. */
data object EarningsDest {
    const val ARG_RANGE = EarningsViewModel.ARG_RANGE
    const val ROUTE = "earnings?range={$ARG_RANGE}"

    /** Plain constant base (no arg) used by the More hub link. */
    const val ROUTE_BASE = "earnings"
}

/** AND-253 — the per-content revenue list route, reached from the earnings dashboard / More hub. */
data object PerContentRevenueDest {
    const val ROUTE = "earnings/per-content"
}

/** AND-252/253 — registers the earnings dashboard + per-content revenue destinations. */
fun NavGraphBuilder.earningsDestinations(navController: NavHostController) {
    composable(
        route = EarningsDest.ROUTE,
        arguments = listOf(
            navArgument(EarningsDest.ARG_RANGE) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        EarningsRoute(
            onBack = { navController.popBackStack() },
            onOpenPerContent = {
                navController.navigate(PerContentRevenueDest.ROUTE) { launchSingleTop = true }
            },
        )
    }
    composable(PerContentRevenueDest.ROUTE) {
        PerContentRevenueRoute(onBack = { navController.popBackStack() })
    }
}
