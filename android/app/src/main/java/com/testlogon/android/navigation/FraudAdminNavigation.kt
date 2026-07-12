package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminfraud.FraudAdminRoute

/**
 * B5 - the admin fraud-review queue, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/fraud page (flags queue + review; cases + resolve). Root-only
 * config / freeze / risk actions are deferred.
 */
data object FraudAdminDest {
    const val ROUTE = "admin/fraud"
}

fun NavGraphBuilder.fraudAdminDestination(navController: NavHostController) {
    composable(FraudAdminDest.ROUTE) {
        FraudAdminRoute(onBack = { navController.popBackStack() })
    }
}
