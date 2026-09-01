package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.maintenance.MaintenanceOrdersRoute

/**
 * WOV — the Maintenance Work Orders destination (reached from the More hub). Mirrors web
 * /ui/maintenance-orders. List + create + status transition; degrades to an "unavailable" state when the
 * MAINTENANCE_ORDERS_ENABLED flag is off (the backend 404s).
 */
data object MaintenanceOrdersDest {
    const val ROUTE = "maintenance/work-orders"
}

/** Registers the Maintenance Work Orders destination. */
fun NavGraphBuilder.maintenanceOrdersDestination(navController: NavHostController) {
    composable(MaintenanceOrdersDest.ROUTE) {
        MaintenanceOrdersRoute(onBack = { navController.popBackStack() })
    }
}
