package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.workflow.WorkflowRulesRoute

/**
 * WFL — the SuiteCRM Workflow admin destination (reached from the More hub, operator-only). Mirrors web
 * /ui/admin/crm/workflow. Read-only list of workflow rules; degrades to an "unavailable" state when the
 * CRM_WORKFLOW_ENABLED flag is off (404) or the caller is not an admin (403).
 */
data object WorkflowRulesDest {
    const val ROUTE = "admin/crm/workflow/rules"
}

/** Registers the workflow-rules admin destination. */
fun NavGraphBuilder.workflowRulesDestination(navController: NavHostController) {
    composable(WorkflowRulesDest.ROUTE) {
        WorkflowRulesRoute(onBack = { navController.popBackStack() })
    }
}
