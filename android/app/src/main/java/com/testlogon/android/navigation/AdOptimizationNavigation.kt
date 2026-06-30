package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.optimization.ui.AdOptimizationRoute

/**
 * Web-parity ad OPTIMIZATION panel destination (`ads-optimization`). No nav arg: the VM self-resolves the
 * caller's first ad account -> first campaign. The More-hub registers [ROUTE] directly.
 */
data object AdOptimizationDest {
    const val ROUTE = "ads-optimization"
}

fun NavHostController.navigateToAdOptimization() {
    navigate(AdOptimizationDest.ROUTE) { launchSingleTop = true }
}

fun NavGraphBuilder.adOptimizationDestination(navController: NavHostController) {
    composable(route = AdOptimizationDest.ROUTE) {
        AdOptimizationRoute(onBack = { navController.popBackStack() })
    }
}
