package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.contentcontrols.ui.ContentAdControlsRoute

/**
 * Web-parity CONTENT AD-CONTROLS destination (`ads-content-controls`). No nav arg: the surface is keyed by
 * the caller (per-content overrides, revenue share, and the ad-revenue transparency / breakdown are all
 * scoped to the authenticated user server-side). The More-hub registers [ROUTE] directly.
 */
data object ContentAdControlsDest {
    const val ROUTE = "ads-content-controls"
}

fun NavHostController.navigateToContentAdControls() {
    navigate(ContentAdControlsDest.ROUTE) { launchSingleTop = true }
}

fun NavGraphBuilder.contentAdControlsDestination(navController: NavHostController) {
    composable(route = ContentAdControlsDest.ROUTE) {
        ContentAdControlsRoute(onBack = { navController.popBackStack() })
    }
}
