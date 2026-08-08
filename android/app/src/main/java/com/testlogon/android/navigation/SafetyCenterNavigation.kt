package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.safety.SafetyCenterRoute

/**
 * PAR-27 — the Safety Center hub destination (`safety_center`). Aggregation only: an arg-less landing
 * that links to four already-registered child destinations (blocked users / privacy export / DMCA /
 * account deletion). Entering while unauthenticated is handled by the authenticated graph's gate.
 */
data object SafetyCenterDest {
    const val ROUTE = "safety_center"
}

/** PAR-27 — navigation seam used by the More/Safety entry. */
fun NavController.navigateToSafetyCenter() {
    navigate(SafetyCenterDest.ROUTE) { launchSingleTop = true }
}

/** PAR-27 — registers the `safety_center` hub; each row navigates to an existing child route. */
fun NavGraphBuilder.safetyCenterDestination(navController: NavHostController) {
    composable(route = SafetyCenterDest.ROUTE) {
        SafetyCenterRoute(
            onBack = { navController.popBackStack() },
            onOpenBlockedUsers = { navController.navigate(BlockedUsersDest.ROUTE) { launchSingleTop = true } },
            onOpenPrivacyExport = { navController.navigateToPrivacyExport() },
            onOpenDmca = { navController.navigate(DmcaDest.STANDALONE_ROUTE) { launchSingleTop = true } },
            onOpenAccountDeletion = { navController.navigateToAccountDeletion() },
        )
    }
}
