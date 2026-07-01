package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.licenses.LicensesRoute
import com.testlogon.android.feature.licenses.compliance.ComplianceRoute
import com.testlogon.android.feature.licenses.requests.LicenseRequestsRoute
import com.testlogon.android.feature.licenses.revenue.LicenseRevenueRoute

/** The content-licensing hub route + its sub-screens (reached from the More hub). Mirrors web /licenses. */
data object LicensesDest {
    const val ROUTE = "licenses"
    const val COMPLIANCE_ROUTE = "licenses/compliance"
    const val REQUESTS_ROUTE = "licenses/requests"
    const val REVENUE_ROUTE = "licenses/revenue"
}

/** Registers the licensing-hub destination + compliance/requests/revenue sub-screens. */
fun NavGraphBuilder.licensesDestination(navController: NavHostController) {
    composable(LicensesDest.ROUTE) {
        LicensesRoute(
            onBack = { navController.popBackStack() },
            // SessionExpired routing is owned by the app shell's auth-gated router; pop back toward it.
            onSessionExpired = { navController.popBackStack() },
            onOpenCompliance = { navController.navigate(LicensesDest.COMPLIANCE_ROUTE) },
            onOpenRequests = { navController.navigate(LicensesDest.REQUESTS_ROUTE) },
            onOpenRevenue = { navController.navigate(LicensesDest.REVENUE_ROUTE) },
        )
    }
    composable(LicensesDest.COMPLIANCE_ROUTE) {
        ComplianceRoute(onBack = { navController.popBackStack() })
    }
    composable(LicensesDest.REQUESTS_ROUTE) {
        LicenseRequestsRoute(onBack = { navController.popBackStack() })
    }
    composable(LicensesDest.REVENUE_ROUTE) {
        LicenseRevenueRoute(onBack = { navController.popBackStack() })
    }
}
