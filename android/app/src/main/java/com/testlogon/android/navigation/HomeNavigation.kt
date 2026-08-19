package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.home.HomeRoute
import com.testlogon.android.feature.home.HomeTarget

/**
 * The Trading Home / Dashboard — a read-only launch surface (portfolio summary, watchlist snapshot,
 * recent activity, quick actions, getting-started checklist), reached from the top of the More ->
 * Wallet hub. It owns no data routes: every tap is delegated to an EXISTING authenticated-graph
 * destination (Markets / Custody / Portfolio / PnL / Price alerts / Blotter). Not the app start
 * destination.
 */
data object HomeDest {
    const val ROUTE = "home"
}

/** Registers the Home dashboard, mapping each [HomeTarget] + a watchlist tap to an existing route. */
fun NavGraphBuilder.homeDestination(navController: NavHostController) {
    composable(HomeDest.ROUTE) {
        HomeRoute(
            onBack = { navController.popBackStack() },
            onOpenSymbol = { symbolId ->
                navController.navigate(SymbolDetailDest.build(symbolId)) { launchSingleTop = true }
            },
            onOpenTarget = { target ->
                val route = when (target) {
                    // Order entry lives on the per-symbol detail; the Markets list is the entry point.
                    HomeTarget.TRADE -> MarketsDest.ROUTE
                    // Funding surface (custody deposit / spot / margin funding bridge).
                    HomeTarget.DEPOSIT -> CustodyDest.ROUTE
                    HomeTarget.PORTFOLIO -> PortfolioDest.ROUTE
                    HomeTarget.PNL -> PnlDest.ROUTE
                    HomeTarget.PRICE_ALERTS -> PriceAlertsDest.ROUTE
                    // Trade history = the fills blotter.
                    HomeTarget.TRADE_HISTORY -> BlotterDest.ROUTE
                }
                navController.navigate(route) { launchSingleTop = true }
            },
        )
    }
}
