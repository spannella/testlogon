package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.infrabilling.ComputeBillingRoute
import com.testlogon.android.feature.infraec2.Ec2Route
import com.testlogon.android.feature.infrahosts.HostInventoryRoute
import com.testlogon.android.feature.infrak8s.K8sRoute
import com.testlogon.android.feature.inframonitoring.InstanceMonitoringRoute
import com.testlogon.android.feature.infrasg.SecurityGroupsRoute

/**
 * B7 web-parity: the CLOUD-INFRA management surfaces, registered in the AUTHENTICATED graph. Mirror the
 * web remote (/remote) pages (Ec2LauncherPage, K8sLauncherPage, SecurityGroupsPage, HostInventoryPage,
 * InstanceMonitoringPage, ComputeSpendingPage). Backends are owner-scoped require_ui_session control
 * planes; a 403 (defence-in-depth) renders Forbidden. Surfaced in the operator/Infra hub (operatorOnly).
 */
data object Ec2Dest {
    const val ROUTE = "infra/ec2"
}

data object K8sDest {
    const val ROUTE = "infra/k8s"
}

data object SecurityGroupsDest {
    const val ROUTE = "infra/security-groups"
}

data object HostInventoryDest {
    const val ROUTE = "infra/hosts"
}

data object InstanceMonitoringDest {
    const val ROUTE = "infra/monitoring"
}

data object ComputeBillingDest {
    const val ROUTE = "infra/billing"
}

fun NavGraphBuilder.cloudInfraDestinations(navController: NavHostController) {
    composable(Ec2Dest.ROUTE) {
        Ec2Route(onBack = { navController.popBackStack() })
    }
    composable(K8sDest.ROUTE) {
        K8sRoute(onBack = { navController.popBackStack() })
    }
    composable(SecurityGroupsDest.ROUTE) {
        SecurityGroupsRoute(onBack = { navController.popBackStack() })
    }
    composable(HostInventoryDest.ROUTE) {
        HostInventoryRoute(onBack = { navController.popBackStack() })
    }
    composable(InstanceMonitoringDest.ROUTE) {
        InstanceMonitoringRoute(onBack = { navController.popBackStack() })
    }
    composable(ComputeBillingDest.ROUTE) {
        ComputeBillingRoute(onBack = { navController.popBackStack() })
    }
}
