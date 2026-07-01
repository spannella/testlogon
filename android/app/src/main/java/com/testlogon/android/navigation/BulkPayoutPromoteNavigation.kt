package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.payouts.BulkPayoutPromoteRoute

/**
 * Web-parity admin bulk-payout PROMOTE console (eligible -> preview -> EXECUTE), registered in the
 * AUTHENTICATED graph. ADMIN-gated (require_admin_or_root) - the ViewModel maps a backend 403 to the
 * Forbidden state. Mirrors the write half of the web /admin/bulk-payouts console. ADDITIVE to the
 * existing READ-ONLY bulk-payout batch list/detail (BulkPayoutsDest, AND-261). EXECUTE moves real funds
 * and is gated behind an explicit confirm dialog in the screen.
 */
data object BulkPayoutPromoteDest {
    const val ROUTE = "payouts/bulk/promote"
}

fun NavGraphBuilder.bulkPayoutPromoteDestination(navController: NavHostController) {
    composable(BulkPayoutPromoteDest.ROUTE) {
        BulkPayoutPromoteRoute(onBack = { navController.popBackStack() })
    }
}
