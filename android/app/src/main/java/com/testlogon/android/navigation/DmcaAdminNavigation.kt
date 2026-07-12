package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.admindmca.DmcaAdminRoute

/**
 * B5 - the admin DMCA claims dashboard, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/dmca page (claims queue + resolve). agent-config PUT is root-only, deferred.
 */
data object DmcaAdminDest {
    const val ROUTE = "admin/dmca"
}

fun NavGraphBuilder.dmcaAdminDestination(navController: NavHostController) {
    composable(DmcaAdminDest.ROUTE) {
        DmcaAdminRoute(onBack = { navController.popBackStack() })
    }
}
