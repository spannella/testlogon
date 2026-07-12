package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminroot.AdminRolesRoute
import com.testlogon.android.feature.adminroot.AdminSsoRoute
import com.testlogon.android.feature.adminroot.AdminTenantsRoute
import com.testlogon.android.feature.adminroot.AdminTiersRoute

/**
 * Web-parity ROOT/ADMIN governance destinations (registered in the AUTHENTICATED graph):
 *  - tenants (/v1/admin/tenants, require_root_session) -> ROOT-GATED, renders Forbidden for admin
 *  - SSO providers (/v1/admin/sso/providers, require_root_session) -> ROOT-GATED, renders Forbidden
 *  - role management (/admin/roles, require_root) -> ROOT-GATED, renders Forbidden
 *  - subscription-tier MANAGER (/ui/admin/subscription-tiers, require_admin_or_root) -> ADMIN-drivable
 * Each screen self-gates on a backend 403.
 */
data object AdminTenantsDest { const val ROUTE = "admin/tenants" }
data object AdminSsoDest { const val ROUTE = "admin/sso" }
data object AdminRolesDest { const val ROUTE = "admin/roles" }
data object AdminTierManagerDest { const val ROUTE = "admin/subscription-tiers" }

fun NavGraphBuilder.adminRootDestinations(navController: NavHostController) {
    composable(AdminTenantsDest.ROUTE) {
        AdminTenantsRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminSsoDest.ROUTE) {
        AdminSsoRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminRolesDest.ROUTE) {
        AdminRolesRoute(onBack = { navController.popBackStack() })
    }
    composable(AdminTierManagerDest.ROUTE) {
        AdminTiersRoute(onBack = { navController.popBackStack() })
    }
}
