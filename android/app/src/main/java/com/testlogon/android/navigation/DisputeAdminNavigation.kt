package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.admindisputes.DisputeAdminRoute

/**
 * B5 - the admin billing-disputes queue, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/disputes page (status-filtered queue + respond/resolve).
 */
data object DisputeAdminDest {
    const val ROUTE = "admin/disputes"
}

fun NavGraphBuilder.disputeAdminDestination(navController: NavHostController) {
    composable(DisputeAdminDest.ROUTE) {
        DisputeAdminRoute(onBack = { navController.popBackStack() })
    }
}
