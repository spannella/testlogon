package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.pmideas.PmIdeasRoute

/**
 * B4 web-parity — PM-agent feature-idea TRIAGE route (web /agents/pm/ideas). Backend `require_ui_session`
 * (agent_pm.py) -> NOT admin-gated (usable by the test user), though the web surfaces it in the operator
 * area. Distinct from the member idea-SUBMIT flow (feature/ideas -> /ui/agents/ideas).
 */
data object PmIdeasDest {
    const val ROUTE = "pm/ideas"
}

fun NavGraphBuilder.pmIdeasDestinations(navController: NavHostController) {
    composable(PmIdeasDest.ROUTE) {
        PmIdeasRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
