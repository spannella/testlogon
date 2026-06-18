package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.alerts.AlertsRoute

/** The alerts-inbox route (reached from the More hub). Mirrors the web /alerts page. */
data object AlertsDest {
    const val ROUTE = "alerts"
}

/** Registers the alerts-inbox destination in the authenticated graph. */
fun NavGraphBuilder.alertsDestination(navController: NavHostController) {
    composable(AlertsDest.ROUTE) {
        AlertsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
