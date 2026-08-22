package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.portfolioanalytics.PortfolioAnalyticsRoute

/**
 * The read-only Portfolio Allocation & Risk Analytics surface, reached from the More -> Wallet hub.
 * Client-computes allocation / concentration / exposure / risk (vol + VaR + diversification) from the
 * existing cross-venue holding reads (custody / spot / margin / tokens / funds / staking); each source
 * degrades independently. No order entry, no money movement.
 */
data object PortfolioAnalyticsDest {
    const val ROUTE = "portfolio_analytics"
}

/** Registers the Portfolio Analytics screen in the authenticated graph. Up / Back pops the stack. */
fun NavGraphBuilder.portfolioAnalyticsDestination(navController: NavHostController) {
    composable(PortfolioAnalyticsDest.ROUTE) {
        PortfolioAnalyticsRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
