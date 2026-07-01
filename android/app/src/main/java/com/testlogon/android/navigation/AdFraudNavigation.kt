package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adfraud.AdFraudDashboardRoute

/**
 * Web-parity admin AD-FRAUD dashboard, registered in the AUTHENTICATED graph. ADMIN-gated
 * (require_admin_or_root) - the ViewModel maps a backend 403 to the Forbidden state. Mirrors the web
 * /admin/ads/fraud page. Distinct from the existing `adminfraud` module (which is /v1/admin/fraud user
 * fraud/risk cases).
 */
data object AdFraudDest {
    const val ROUTE = "admin/ads/fraud"
}

fun NavGraphBuilder.adFraudDestination(navController: NavHostController) {
    composable(AdFraudDest.ROUTE) {
        AdFraudDashboardRoute(onBack = { navController.popBackStack() })
    }
}
