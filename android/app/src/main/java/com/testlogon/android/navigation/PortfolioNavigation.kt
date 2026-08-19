package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.portfolio.PortfolioRoute

/**
 * The read-only Portfolio (cross-venue account overview) surface, reached from the More -> Wallet hub.
 * Aggregates custody / spot / margin / staking reads into one snapshot; each source degrades
 * independently. No order entry, no money movement.
 */
data object PortfolioDest {
    const val ROUTE = "portfolio"
}

/** Registers the Portfolio screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.portfolioDestination(navController: NavHostController) {
    composable(PortfolioDest.ROUTE) {
        PortfolioRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
