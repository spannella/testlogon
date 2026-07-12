package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.appeals.AppealsRoute

/** The "My appeals" route (reached from the More hub). Mirrors the web /appeals page. */
data object AppealsDest {
    const val ROUTE = "appeals"
}

/** Registers the appeals destination in the authenticated graph. */
fun NavGraphBuilder.appealsDestination(navController: NavHostController) {
    composable(AppealsDest.ROUTE) {
        AppealsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
