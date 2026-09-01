package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.hr.HrEmploymentDetailRoute
import com.testlogon.android.feature.hr.HrEmploymentDetailViewModel
import com.testlogon.android.feature.hr.HrHubRoute
import com.testlogon.android.feature.hr.HrPayrollDetailRoute
import com.testlogon.android.feature.hr.HrPayrollDetailViewModel

/** HRM-009 — the HR hub route (operator-only; reached from the More hub). */
data object HrHubDest {
    const val ROUTE = "hr"
}

/** HRM-009 — employment detail route; arg is the STRING employment_id. */
data object HrEmploymentDetailDest {
    const val ARG = HrEmploymentDetailViewModel.ARG_EMPLOYMENT_ID
    const val ROUTE = "hr/employments/{$ARG}"

    fun build(employmentId: String): String = "hr/employments/${Uri.encode(employmentId)}"
}

/** HRM-009 — payroll-run detail route; arg is the STRING payroll_run_id. */
data object HrPayrollDetailDest {
    const val ARG = HrPayrollDetailViewModel.ARG_PAYROLL_RUN_ID
    const val ROUTE = "hr/payroll/{$ARG}"

    fun build(payrollRunId: String): String = "hr/payroll/${Uri.encode(payrollRunId)}"
}

/** HRM-009 — registers the HR hub + detail destinations in the authenticated graph. */
fun NavGraphBuilder.hrDestinations(navController: NavHostController) {
    composable(HrHubDest.ROUTE) {
        HrHubRoute(
            onEmploymentClick = { id ->
                navController.navigate(HrEmploymentDetailDest.build(id)) { launchSingleTop = true }
            },
            onPayrollClick = { id ->
                navController.navigate(HrPayrollDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = HrEmploymentDetailDest.ROUTE,
        arguments = listOf(navArgument(HrEmploymentDetailDest.ARG) { type = NavType.StringType }),
    ) {
        HrEmploymentDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(
        route = HrPayrollDetailDest.ROUTE,
        arguments = listOf(navArgument(HrPayrollDetailDest.ARG) { type = NavType.StringType }),
    ) {
        HrPayrollDetailRoute(onBack = { navController.popBackStack() })
    }
}
