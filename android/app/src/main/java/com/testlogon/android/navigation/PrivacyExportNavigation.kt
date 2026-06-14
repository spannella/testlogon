package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.privacy.PrivacyExportRoute

/**
 * AND-385 - the Privacy & Data Export destination (Settings -> Privacy). Arg-less: the screen tracks the
 * authenticated user's export requests from GET /ui/privacy/requests and the create POST. Entering while
 * unauthenticated is handled by the authenticated graph's gate + the AND-027 401 interceptor.
 */
data object PrivacyExportDest {
    const val ROUTE = "privacy_export"
}

/** AND-385 - navigation seam used by the Settings/More entry. */
fun NavController.navigateToPrivacyExport() {
    navigate(PrivacyExportDest.ROUTE) { launchSingleTop = true }
}

/** AND-385 - registers the `privacy_export` destination. */
fun NavGraphBuilder.privacyExportDestination(navController: NavHostController) {
    composable(route = PrivacyExportDest.ROUTE) {
        PrivacyExportRoute(onBack = { navController.popBackStack() })
    }
}
