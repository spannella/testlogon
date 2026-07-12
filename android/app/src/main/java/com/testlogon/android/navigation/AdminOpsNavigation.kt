package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminops.AuditExportsRoute
import com.testlogon.android.feature.adminops.ComputeRoute
import com.testlogon.android.feature.adminops.FinancialsRoute
import com.testlogon.android.feature.adminops.JobsRoute
import com.testlogon.android.feature.adminops.PaymentHealthRoute
import com.testlogon.android.feature.adminops.RateLimitsRoute
import com.testlogon.android.feature.adminops.RiskRoute

/**
 * B6 admin-ops read dashboards (financials / payment-health / risk / compute / jobs / rate-limits /
 * audit-exports), registered in the AUTHENTICATED graph. Each screen self-gates on a backend 403 ->
 * Forbidden state. Reads on financials/payment-health/risk/compute/jobs are ADMIN-drivable; rate-limits
 * and audit-exports are ROOT-only (they render Forbidden for our admin account). Mirrors the web admin pages.
 */
data object AdminOpsFinancialsDest { const val ROUTE = "admin/financials" }
data object AdminOpsPaymentHealthDest { const val ROUTE = "admin/payment-health" }
data object AdminOpsRiskDest { const val ROUTE = "admin/risk" }
data object AdminOpsComputeDest { const val ROUTE = "admin/compute" }
data object AdminOpsJobsDest { const val ROUTE = "admin/jobs" }
data object AdminOpsRateLimitsDest { const val ROUTE = "admin/rate-limits" }
data object AdminOpsAuditExportsDest { const val ROUTE = "admin/audit-exports" }

fun NavGraphBuilder.adminOpsDestinations(navController: NavHostController) {
    composable(AdminOpsFinancialsDest.ROUTE) {
        FinancialsRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsPaymentHealthDest.ROUTE) {
        PaymentHealthRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsRiskDest.ROUTE) {
        RiskRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsComputeDest.ROUTE) {
        ComputeRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsJobsDest.ROUTE) {
        JobsRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsRateLimitsDest.ROUTE) {
        RateLimitsRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminOpsAuditExportsDest.ROUTE) {
        AuditExportsRoute(onBack = { navController.popBackStack() })
    }
}
