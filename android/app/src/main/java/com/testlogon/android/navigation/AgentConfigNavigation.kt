package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.agentconfig.AgentConfigsRoute
import com.testlogon.android.feature.agentconfig.AgentTypeConfigRoute

/**
 * B4 web-parity - agent-type config routes (web /agents/types/:typeId/{coder,qa,devops,architect,pm}).
 * A landing hub ([AgentConfigsHubDest]) lists the five types + a typeId entry; drilling in opens the ONE
 * parametrized config screen ([AgentConfigDest]) keyed by {type}/{typeId}. Reached from the More hub under
 * Support (operator-gated: hidden from non-operators, and the backend 403s -> Forbidden state).
 */
data object AgentConfigsHubDest {
    const val ROUTE = "agent-configs"
}

data object AgentConfigDest {
    const val ARG_TYPE = "type"
    const val ARG_TYPE_ID = "typeId"
    const val ROUTE_BASE = "agent-configs/type"
    const val ROUTE = "$ROUTE_BASE/{$ARG_TYPE}/{$ARG_TYPE_ID}"

    fun route(type: String, typeId: String): String =
        "$ROUTE_BASE/$type/${typeId.ifBlank { type }}"
}

fun NavGraphBuilder.agentConfigDestinations(navController: NavHostController) {
    composable(AgentConfigsHubDest.ROUTE) {
        AgentConfigsRoute(
            onBack = { navController.popBackStack() },
            onOpen = { type, typeId ->
                navController.navigate(AgentConfigDest.route(type, typeId))
            },
        )
    }
    composable(
        route = AgentConfigDest.ROUTE,
        arguments = listOf(
            navArgument(AgentConfigDest.ARG_TYPE) { type = NavType.StringType },
            navArgument(AgentConfigDest.ARG_TYPE_ID) { type = NavType.StringType },
        ),
    ) {
        AgentTypeConfigRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
