package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kycadmin.KycAddressVerifAdminRoute
import com.testlogon.android.feature.kycadmin.KycAnalyticsAdminRoute
import com.testlogon.android.feature.kycadmin.KycComplianceAdminRoute
import com.testlogon.android.feature.kycadmin.KycMetricsAdminRoute
import com.testlogon.android.feature.kycadmin.KycMonitoringAdminRoute
import com.testlogon.android.feature.kycadmin.KycTemplatesAdminRoute
import com.testlogon.android.feature.kycadmin.KycTranslationsAdminRoute
import com.testlogon.android.feature.kycadmin.KycWorkloadAdminRoute

/**
 * KYC-admin DASHBOARDS + CONFIG destinations (B2..B9), registered in the AUTHENTICATED graph. Each
 * mirrors a web admin KYC page and self-gates on a backend 403 -> Forbidden state (our admin
 * account drives them; the ROOT-only SLA-config write and PII key ops are intentionally not surfaced).
 */
data object KycWorkloadAdminDest { const val ROUTE = "admin/kyc/workload" }
data object KycMetricsAdminDest { const val ROUTE = "admin/kyc/metrics" }
data object KycAnalyticsAdminDest { const val ROUTE = "admin/kyc/analytics" }
data object KycMonitoringAdminDest { const val ROUTE = "admin/kyc/monitoring" }
data object KycAddressVerifAdminDest { const val ROUTE = "admin/kyc/address-verification" }
data object KycComplianceAdminDest { const val ROUTE = "admin/kyc/compliance" }
data object KycTemplatesAdminDest { const val ROUTE = "admin/kyc/templates" }
data object KycTranslationsAdminDest { const val ROUTE = "admin/kyc/translations" }

fun NavGraphBuilder.kycAdminDashboardDestinations(navController: NavHostController) {
    composable(KycWorkloadAdminDest.ROUTE) { KycWorkloadAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycMetricsAdminDest.ROUTE) { KycMetricsAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycAnalyticsAdminDest.ROUTE) { KycAnalyticsAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycMonitoringAdminDest.ROUTE) { KycMonitoringAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycAddressVerifAdminDest.ROUTE) { KycAddressVerifAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycComplianceAdminDest.ROUTE) { KycComplianceAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycTemplatesAdminDest.ROUTE) { KycTemplatesAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycTranslationsAdminDest.ROUTE) { KycTranslationsAdminRoute(onBack = { navController.popBackStack() }) }
}
