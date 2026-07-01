package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.R
import com.testlogon.android.feature.compliance.ComplianceRoute

/**
 * B4 web-parity — Compliance / Security agent routes.
 *
 * Web quirk: /agents/security, /agents/security/findings, /agents/security/audits ALL render the same
 * ComplianceAgentConfigPage as /agents/compliance (security == the compliance page; endpoints are the
 * compliance router's findings/audits). So every route here mounts the one [ComplianceRoute] (Findings /
 * Audits / Compliance / Trends tabs), differing only by title. All backend `require_ui_session`
 * (agent_compliance.py) -> usable by the test user.
 */
data object ComplianceDest {
    const val ROUTE = "compliance"
}

data object SecurityDest {
    const val ROUTE = "security"
    const val FINDINGS_ROUTE = "security/findings"
    const val AUDITS_ROUTE = "security/audits"
}

fun NavGraphBuilder.complianceDestinations(navController: NavHostController) {
    composable(ComplianceDest.ROUTE) {
        ComplianceRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            titleRes = R.string.compliance_title,
        )
    }
    listOf(SecurityDest.ROUTE, SecurityDest.FINDINGS_ROUTE, SecurityDest.AUDITS_ROUTE).forEach { route ->
        composable(route) {
            ComplianceRoute(
                onBack = { navController.popBackStack() },
                onSessionExpired = { navController.popBackStack() },
                titleRes = R.string.security_title,
            )
        }
    }
}
