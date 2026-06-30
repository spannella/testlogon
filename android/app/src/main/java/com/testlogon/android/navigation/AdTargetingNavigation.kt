package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.targeting.ui.AdTargetingRoute

/**
 * Web-parity ad TARGETING editor destination (`ads-targeting`). No nav arg: the VM self-resolves the
 * caller's first ad account -> first campaign (there is no campaign-picker nav yet), mirroring the read-only
 * AdsCampaigns self-heal. The More-hub registers [ROUTE] directly.
 */
data object AdTargetingDest {
    const val ROUTE = "ads-targeting"
}

fun NavHostController.navigateToAdTargeting() {
    navigate(AdTargetingDest.ROUTE) { launchSingleTop = true }
}

fun NavGraphBuilder.adTargetingDestination(navController: NavHostController) {
    composable(route = AdTargetingDest.ROUTE) {
        AdTargetingRoute(onBack = { navController.popBackStack() })
    }
}
