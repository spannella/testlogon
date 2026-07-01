package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.admintax.AdminTaxFormRoute

/**
 * Web-parity admin 1099 MANAGER, registered in the AUTHENTICATED graph. ADMIN-gated
 * (require_admin_or_root) - the ViewModel maps a backend 403 to the Forbidden state. Mirrors the web
 * /admin/tax-forms-1099 page. Distinct from the existing user-facing `taxforms` module (own 1099 only).
 */
data object AdminTaxFormDest {
    const val ROUTE = "admin/tax-forms-1099"
}

fun NavGraphBuilder.adminTaxFormDestination(navController: NavHostController) {
    composable(AdminTaxFormDest.ROUTE) {
        AdminTaxFormRoute(onBack = { navController.popBackStack() })
    }
}
