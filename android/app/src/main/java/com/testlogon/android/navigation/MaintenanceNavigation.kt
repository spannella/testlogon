package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.maintenance.MaintenanceOrdersRoute
import com.testlogon.android.feature.maintenance.VendorsRoute

/**
 * WOV — the Maintenance Work Orders destination (reached from the More hub) + the Vendors directory
 * destination (reached from the Work Orders top bar). Mirrors web /ui/maintenance-orders +
 * /ui/maintenance/vendors. Both degrade to an "unavailable" state when the MAINTENANCE_ORDERS_ENABLED
 * flag is off (the backend 404s).
 */
data object MaintenanceOrdersDest {
    const val ROUTE = "maintenance/work-orders"
}

/** WOV-004 — the Maintenance Vendors directory destination. */
data object MaintenanceVendorsDest {
    const val ROUTE = "maintenance/vendors"
}

/** Registers the Maintenance Work Orders + Vendors destinations. */
fun NavGraphBuilder.maintenanceOrdersDestination(navController: NavHostController) {
    composable(MaintenanceOrdersDest.ROUTE) {
        MaintenanceOrdersRoute(
            onBack = { navController.popBackStack() },
            onOpenVendors = { navController.navigate(MaintenanceVendorsDest.ROUTE) },
        )
    }
    composable(MaintenanceVendorsDest.ROUTE) {
        VendorsRoute(onBack = { navController.popBackStack() })
    }
}
