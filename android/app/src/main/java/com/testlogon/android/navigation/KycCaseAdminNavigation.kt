package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kycadmin.KycCaseAdminRoute

/**
 * A1 — the main KYC case review queue (queue + case detail + approve/reject/request-info). Web-parity
 * /admin/kyc. Registered in the AUTHENTICATED graph; admin-gated (backend 403 -> Forbidden).
 */
data object KycCaseAdminDest {
    const val ROUTE = "admin/kyc/cases"
}

fun NavGraphBuilder.kycCaseAdminDestination(navController: NavHostController) {
    composable(KycCaseAdminDest.ROUTE) {
        KycCaseAdminRoute(onBack = { navController.popBackStack() })
    }
}
