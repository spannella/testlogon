package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.invest.InvestRoute

/**
 * The unified INVEST hub destination, registered in the AUTHENTICATED nav graph.
 *
 * [InvestDest] is a single navigable screen that aggregates every investable/tradeable product
 * (markets, creator tokens, strategy funds, staking, opportunities) client-side. It does NOT own any
 * detail routes: each card + "See all" navigates to the EXISTING per-product destination already
 * registered in this same graph (markets/tokens/strategies/custody/bailout), so the hub is a pure
 * front door. A blank/absent route from an item is treated as non-navigable and ignored.
 */
data object InvestDest {
    const val ROUTE = "invest"
}

/** Registers the Invest hub destination (Back pops the stack; items navigate to existing screens). */
fun NavGraphBuilder.investDestinations(navController: NavHostController) {
    composable(InvestDest.ROUTE) {
        InvestRoute(
            onBack = { navController.popBackStack() },
            onOpenRoute = { route ->
                if (route.isNotBlank()) {
                    navController.navigate(route) { launchSingleTop = true }
                }
            },
        )
    }
}
