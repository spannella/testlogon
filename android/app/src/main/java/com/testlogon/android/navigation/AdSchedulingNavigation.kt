package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.scheduling.ui.AdSchedulingRoute

/**
 * Web-parity ad SCHEDULING (dayparting + flights) editor destination (`ads-scheduling`). No nav arg: the VM
 * self-resolves the caller's first ad account -> first campaign. The More-hub registers [ROUTE] directly.
 */
data object AdSchedulingDest {
    const val ROUTE = "ads-scheduling"
}

fun NavHostController.navigateToAdScheduling() {
    navigate(AdSchedulingDest.ROUTE) { launchSingleTop = true }
}

fun NavGraphBuilder.adSchedulingDestination(navController: NavHostController) {
    composable(route = AdSchedulingDest.ROUTE) {
        AdSchedulingRoute(onBack = { navController.popBackStack() })
    }
}
