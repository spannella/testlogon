package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.agents.run.ui.AgentRunConsoleRoute
import com.testlogon.android.feature.agents.run.ui.AgentRunConsoleViewModel
import com.testlogon.android.feature.agents.run.ui.AgentRunHubRoute

/**
 * AGENT-RUN (web-parity) - destinations for the generic agent-run CONSOLE (mobile mirror of the web
 * *RunOutputPanel / DeploymentApprovalPanel family). A hub ([AgentRunHubDest]) lists the six executable agent
 * types + a typeId override; drilling in opens the ONE parametrized console ([AgentRunConsoleDest]) keyed by
 * {type}/{typeId}. Reached from the More hub under Support (operator-gated: hidden from non-operators, and the
 * backend 403s -> Forbidden state). Registered inside the existing agents feature graph (no new nav-route
 * literal beyond these two, which live under the "agent-run" prefix).
 */
data object AgentRunHubDest {
    const val ROUTE = "agent-run"
}

data object AgentRunConsoleDest {
    const val ARG_TYPE = AgentRunConsoleViewModel.ARG_TYPE
    const val ARG_TYPE_ID = AgentRunConsoleViewModel.ARG_TYPE_ID
    const val ROUTE_BASE = "agent-run/console"
    const val ROUTE = "$ROUTE_BASE/{$ARG_TYPE}/{$ARG_TYPE_ID}"

    fun route(type: String, typeId: String): String =
        "$ROUTE_BASE/$type/${typeId.ifBlank { type }}"
}

fun NavGraphBuilder.agentRunDestinations(navController: NavHostController) {
    composable(AgentRunHubDest.ROUTE) {
        AgentRunHubRoute(
            onBack = { navController.popBackStack() },
            onOpen = { type, typeId ->
                navController.navigate(AgentRunConsoleDest.route(type, typeId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = AgentRunConsoleDest.ROUTE,
        arguments = listOf(
            navArgument(AgentRunConsoleDest.ARG_TYPE) { type = NavType.StringType },
            navArgument(AgentRunConsoleDest.ARG_TYPE_ID) { type = NavType.StringType },
        ),
    ) {
        AgentRunConsoleRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = {
                navController.navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) {
                    launchSingleTop = true
                }
            },
        )
    }
}
