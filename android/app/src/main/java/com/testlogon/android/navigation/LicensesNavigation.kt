package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.licenses.LicensesRoute

/** The content-licensing hub route (reached from the More hub). Mirrors the web /licenses routes. */
data object LicensesDest {
    const val ROUTE = "licenses"
}

/** Registers the licensing-hub destination in the authenticated graph. */
fun NavGraphBuilder.licensesDestination(navController: NavHostController) {
    composable(LicensesDest.ROUTE) {
        LicensesRoute(
            onBack = { navController.popBackStack() },
            // SessionExpired routing is owned by the app shell's auth-gated router; pop back toward it.
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
