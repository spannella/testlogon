package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.feetiers.FeeTiersRoute

/**
 * The maker/taker FEE TIER (VIP schedule) surface, reached from the More -> Wallet hub (near Tax).
 * Shows the caller's current tier + rates, their trailing 30-day trading volume (client-computed from
 * the live fills feed, same source as the Tax report; overridden by an authoritative backend read when
 * deployed), progress to the next tier, and the full canonical schedule. No money movement.
 */
data object FeeTiersDest {
    const val ROUTE = "fee_tiers"
}

/** Registers the Fee Tiers screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.feeTiersDestination(navController: NavHostController) {
    composable(FeeTiersDest.ROUTE) {
        FeeTiersRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
