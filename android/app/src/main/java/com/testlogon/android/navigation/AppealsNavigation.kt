package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.appeals.AppealsRoute

/** The "My appeals" route (reached from the More hub). Mirrors the web /appeals page.
 * MODX-13: an optional ``enforcement`` query arg lets a ban/removal alert deep-link straight
 * into the submit form with that enforcement pre-selected. */
data object AppealsDest {
    const val ROUTE = "appeals"
    const val ARG_ENFORCEMENT = "enforcement"
    const val ROUTE_WITH_ARG = "appeals?$ARG_ENFORCEMENT={$ARG_ENFORCEMENT}"
    fun build(enforcementId: String): String = "appeals?$ARG_ENFORCEMENT=$enforcementId"
}

/** Registers the appeals destination in the authenticated graph. */
fun NavGraphBuilder.appealsDestination(navController: NavHostController) {
    composable(
        route = AppealsDest.ROUTE_WITH_ARG,
        arguments = listOf(
            navArgument(AppealsDest.ARG_ENFORCEMENT) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) { entry ->
        val prefill = entry.arguments?.getString(AppealsDest.ARG_ENFORCEMENT)
        AppealsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            prefillEnforcementId = prefill,
        )
    }
}
