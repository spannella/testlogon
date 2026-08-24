package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminrewards.CatalogAdminRoute

/**
 * Operator rewards-catalog admin (CRUD over the redeemable rewards members see), registered in the
 * AUTHENTICATED graph. Role-gated the SAME way as the other admin queues (backend 403 -> Forbidden
 * "not authorised"); the list read degrades on 404 to an honest empty state.
 */
data object CatalogAdminDest {
    const val ROUTE = "admin/rewards/catalog"
}

fun NavGraphBuilder.catalogAdminDestination(navController: NavHostController) {
    composable(CatalogAdminDest.ROUTE) {
        CatalogAdminRoute(onBack = { navController.popBackStack() })
    }
}
