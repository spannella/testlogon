package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kycadmin.KycBusinessAdminRoute
import com.testlogon.android.feature.kycadmin.KycDocAdminRoute
import com.testlogon.android.feature.kycadmin.KycIdScanAdminRoute
import com.testlogon.android.feature.kycadmin.KycLivenessAdminRoute
import com.testlogon.android.feature.kycadmin.KycPofAdminRoute
import com.testlogon.android.feature.kycadmin.KycResidencyAdminRoute
import com.testlogon.android.feature.kycadmin.KycScreeningAdminRoute

/**
 * KYC-admin review-queue destinations (A2..A8), registered in the AUTHENTICATED graph. Each mirrors a
 * web the admin KYC review page and self-gates via the backend 403 -> Forbidden state.
 */
data object KycDocAdminDest { const val ROUTE = "admin/kyc/documents" }
data object KycResidencyAdminDest { const val ROUTE = "admin/kyc/residency" }
data object KycPofAdminDest { const val ROUTE = "admin/kyc/proof-of-funds" }
data object KycLivenessAdminDest { const val ROUTE = "admin/kyc/liveness-call" }
data object KycScreeningAdminDest { const val ROUTE = "admin/kyc/screening" }
data object KycIdScanAdminDest { const val ROUTE = "admin/kyc/id-scanner" }
data object KycBusinessAdminDest { const val ROUTE = "admin/kyc/business" }

fun NavGraphBuilder.kycReviewDestinations(navController: NavHostController) {
    composable(KycDocAdminDest.ROUTE) { KycDocAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycResidencyAdminDest.ROUTE) { KycResidencyAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycPofAdminDest.ROUTE) { KycPofAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycLivenessAdminDest.ROUTE) { KycLivenessAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycScreeningAdminDest.ROUTE) { KycScreeningAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycIdScanAdminDest.ROUTE) { KycIdScanAdminRoute(onBack = { navController.popBackStack() }) }
    composable(KycBusinessAdminDest.ROUTE) { KycBusinessAdminRoute(onBack = { navController.popBackStack() }) }
}
