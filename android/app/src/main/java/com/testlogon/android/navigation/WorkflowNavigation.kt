package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.workflow.DripSequencesRoute
import com.testlogon.android.feature.workflow.WorkflowRulesRoute
import com.testlogon.android.feature.workflow.WorkflowRunsRoute

/**
 * WFL — the SuiteCRM Workflow admin destinations (reached from the More hub, operator-only). Mirrors web
 * /ui/admin/crm/workflow. The rules list is the hub entry (registered in MoreRoutes); the run-history and
 * drip-sequence destinations are internal sub-routes navigated to from the list (they are NOT separate
 * More-hub entries, so no new MoreRoutes literal is added). Everything degrades to an "unavailable" state
 * when CRM_WORKFLOW_ENABLED is off (404) or the caller is not an admin (403).
 */
data object WorkflowRulesDest {
    const val ROUTE = "admin/crm/workflow/rules"
}

/** Internal sub-route: run history for one rule. */
data object WorkflowRunsDest {
    const val ARG_RULE_ID = "ruleId"
    const val ROUTE = "admin/crm/workflow/rules/{$ARG_RULE_ID}/runs"
    fun route(ruleId: String): String = "admin/crm/workflow/rules/$ruleId/runs"
}

/** Internal sub-route: drip-sequence list + create. */
data object WorkflowDripDest {
    const val ROUTE = "admin/crm/workflow/drip-sequences"
}

/** Registers the workflow-rules admin destination + its internal sub-destinations. */
fun NavGraphBuilder.workflowRulesDestination(navController: NavHostController) {
    composable(WorkflowRulesDest.ROUTE) {
        WorkflowRulesRoute(
            onBack = { navController.popBackStack() },
            onOpenRuns = { ruleId -> navController.navigate(WorkflowRunsDest.route(ruleId)) },
            onOpenDrip = { navController.navigate(WorkflowDripDest.ROUTE) },
        )
    }
    composable(
        route = WorkflowRunsDest.ROUTE,
        arguments = listOf(navArgument(WorkflowRunsDest.ARG_RULE_ID) { type = NavType.StringType }),
    ) { backStackEntry ->
        val ruleId = backStackEntry.arguments?.getString(WorkflowRunsDest.ARG_RULE_ID).orEmpty()
        WorkflowRunsRoute(ruleId = ruleId, onBack = { navController.popBackStack() })
    }
    composable(WorkflowDripDest.ROUTE) {
        DripSequencesRoute(onBack = { navController.popBackStack() })
    }
}
