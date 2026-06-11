package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.analytics.engagement.EngagementRoute
import com.testlogon.android.feature.analytics.engagement.EngagementViewModel

/** AND-254 — the engagement-rate analytics route; optional `period` arg deep-links to a day window. */
data object EngagementDest {
    const val ARG_PERIOD = EngagementViewModel.ARG_PERIOD
    const val ROUTE = "analytics/engagement?period={$ARG_PERIOD}"

    /** Plain constant base (no arg) used by the More hub link. */
    const val ROUTE_BASE = "analytics/engagement"
}

/** AND-254 — registers the engagement-rate destination. */
fun NavGraphBuilder.engagementDestinations(navController: NavHostController) {
    composable(
        route = EngagementDest.ROUTE,
        arguments = listOf(
            navArgument(EngagementDest.ARG_PERIOD) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        EngagementRoute(onBack = { navController.popBackStack() })
    }
}
