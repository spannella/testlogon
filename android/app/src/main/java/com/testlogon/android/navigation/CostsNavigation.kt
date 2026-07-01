package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.costs.BudgetsRoute
import com.testlogon.android.feature.costs.CostAlertsRoute
import com.testlogon.android.feature.costs.CostBreakdownRoute
import com.testlogon.android.feature.costs.CostOverviewRoute

/**
 * B4 web-parity — Accountant / cost-tracking agent routes (web /agents/costs, /costs/breakdown,
 * /costs/budgets, /costs/alerts). All backend `require_ui_session` (agent_accountant.py) -> usable by the
 * test user. Overview is the hub entry; it links to breakdown, budgets, and alerts.
 */
data object CostOverviewDest {
    const val ROUTE = "costs"
}

data object CostBreakdownDest {
    const val ROUTE = "costs/breakdown"
}

data object CostBudgetsDest {
    const val ROUTE = "costs/budgets"
}

data object CostAlertsDest {
    const val ROUTE = "costs/alerts"
}

fun NavGraphBuilder.costsDestinations(navController: NavHostController) {
    composable(CostOverviewDest.ROUTE) {
        CostOverviewRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            onOpenBreakdown = { navController.navigate(CostBreakdownDest.ROUTE) },
            onOpenBudgets = { navController.navigate(CostBudgetsDest.ROUTE) },
            onOpenAlerts = { navController.navigate(CostAlertsDest.ROUTE) },
        )
    }
    composable(CostBreakdownDest.ROUTE) {
        CostBreakdownRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
    composable(CostBudgetsDest.ROUTE) {
        BudgetsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
    composable(CostAlertsDest.ROUTE) {
        CostAlertsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
