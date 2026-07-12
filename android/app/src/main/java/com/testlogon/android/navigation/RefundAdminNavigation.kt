package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminrefunds.RefundAdminRoute

/**
 * B5 - the admin refund-requests queue, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/refunds page (status-filtered queue + approve/reject).
 */
data object RefundAdminDest {
    const val ROUTE = "admin/refunds"
}

fun NavGraphBuilder.refundAdminDestination(navController: NavHostController) {
    composable(RefundAdminDest.ROUTE) {
        RefundAdminRoute(onBack = { navController.popBackStack() })
    }
}
