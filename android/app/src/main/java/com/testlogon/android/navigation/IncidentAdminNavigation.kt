package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminincidents.IncidentAdminRoute

/**
 * B5 - the admin payment-incidents queue, registered in the AUTHENTICATED graph. Role-gated (backend 403
 * -> Forbidden). Mirrors the web /admin/payment-incidents page (status-filtered queue + submit-response
 * for dispute incidents).
 */
data object IncidentAdminDest {
    const val ROUTE = "admin/payment-incidents"
}

fun NavGraphBuilder.incidentAdminDestination(navController: NavHostController) {
    composable(IncidentAdminDest.ROUTE) {
        IncidentAdminRoute(onBack = { navController.popBackStack() })
    }
}
