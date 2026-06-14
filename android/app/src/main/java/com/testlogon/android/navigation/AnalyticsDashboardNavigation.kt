package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.analytics.dashboards.AnalyticsDashboardRoute
import com.testlogon.android.feature.analytics.dashboards.AnalyticsDashboardViewModel

/**
 * AND-399 - the account-wide analytics DASHBOARDS route (KPI tiles + views/subscriber charts +
 * top-content/audience breakdowns over a selectable range). Top-level destination: no entity id (the
 * account is resolved server-side from the session). An optional `range` arg deep-links to a preset.
 */
data object AnalyticsDashboardDest {
    const val ARG_RANGE = AnalyticsDashboardViewModel.ARG_RANGE
    const val ROUTE = "analytics/dashboard?range={$ARG_RANGE}"

    /** Plain constant base (no arg) used by the More hub link. */
    const val ROUTE_BASE = "analytics/dashboard"
}

/** AND-399 - registers the analytics-dashboards destination. */
fun NavGraphBuilder.analyticsDashboardDestination(navController: NavHostController) {
    composable(
        route = AnalyticsDashboardDest.ROUTE,
        arguments = listOf(
            navArgument(AnalyticsDashboardDest.ARG_RANGE) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        AnalyticsDashboardRoute(onBack = { navController.popBackStack() })
    }
}
