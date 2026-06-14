package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kyc.TierStatusRoute

/** AND-320 — the KYC Tier Status destination (current tier + requirements checklist + Evaluate). */
data object KycTierDest {
    const val ROUTE = "kyc/tier"
}

/**
 * AND-320 — registers the KYC Tier Status screen in the authenticated graph.
 *
 * [TierStatusRoute.onOpenCase] is wired to a no-op for now: requirements carry no case id and the KYC case
 * screens (E42 / later tickets) are not yet wired, so there is nothing to open. Replace with a real
 * navigate() once the case route lands.
 */
fun NavGraphBuilder.kycTierDestination(navController: NavHostController) {
    composable(KycTierDest.ROUTE) {
        TierStatusRoute(
            onBack = { navController.popBackStack() },
            // KYC case detail route not available yet (E42); see KDoc above.
            onOpenCase = { /* no-op until the KYC case route lands */ },
        )
    }
}
