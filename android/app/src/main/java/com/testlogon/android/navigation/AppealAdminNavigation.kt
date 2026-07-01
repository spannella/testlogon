package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminappeals.AppealAdminRoute

/**
 * B5 - the admin appeals review queue, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/appeals page (status-filtered queue + claim/decide). Distinct from
 * the USER-side appeals surface (feature/appeals -> /v1/appeals).
 */
data object AppealAdminDest {
    const val ROUTE = "admin/appeals"
}

fun NavGraphBuilder.appealAdminDestination(navController: NavHostController) {
    composable(AppealAdminDest.ROUTE) {
        AppealAdminRoute(onBack = { navController.popBackStack() })
    }
}
