package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminemail.AdminEmailRoute

/**
 * Admin-EMAIL management hub (router app/routers/admin_email.py, prefix `/ui/admin/email`, all
 * `require_admin_or_root`). Covers the campaign-email-TEMPLATE CRUD + SUPPRESSED-list management +
 * a compact delivery-stats header. DISTINCT from [MessagingDashboardDest] (the AND-404 READ-ONLY
 * email/SMS delivery dashboard) — this is the MANAGEMENT surface (create/deactivate templates,
 * unsuppress addresses).
 *
 * operator-only in the More catalog; self-gates via the client [AdminRoleProvider] pre-check + the
 * backend 403 -> Forbidden state. Template reads degrade to empty when the campaign-templates flag is
 * off; mutations surface a "not enabled" error.
 */
data object AdminEmailDest {
    const val ROUTE = "admin/email"
}

fun NavGraphBuilder.adminEmailDestinations(navController: NavHostController) {
    composable(AdminEmailDest.ROUTE) {
        AdminEmailRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
