package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.admin.AdminDashboardRoute

/**
 * AND-403 - the READ-ONLY admin alerts/dashboards destination, registered in the AUTHENTICATED nav graph (one
 * shared graph; NOT forked). The route is role-gated by (1) the ViewModel's client-side pre-check (a verified
 * non-admin -> Forbidden, no fetch) and (2) the backend `403` (the final authority), which the screen renders as
 * the non-destructive Forbidden state with a Back action - a non-admin who deep-links here issues no admin data
 * render and is offered Back (AND-403 §4 / FR-8 / AC-2 / TC-14). This mirrors the established admin-screen
 * pattern (the AND-377 helpdesk dashboard / AND-248 billing config self-gate on the 403 signal).
 */
data object AdminDashboardDest {
    const val ROUTE = "admin/dashboard"
}

/** AND-403 - registers the admin dashboard destination (Back pops the back stack). */
fun NavGraphBuilder.adminDashboardDestination(navController: NavHostController) {
    composable(AdminDashboardDest.ROUTE) {
        AdminDashboardRoute(onBack = { navController.popBackStack() })
    }
}
