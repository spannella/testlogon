package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.search.GlobalSearchRoute
import com.testlogon.android.feature.search.SearchActionId
import com.testlogon.android.feature.search.SearchDest
import com.testlogon.android.feature.search.SearchViewModel

/**
 * Global search (symbols + destinations quick-jump), registered in the AUTHENTICATED nav graph.
 *
 * The screen owns no data routes: every tap is delegated to an EXISTING authenticated-graph
 * destination (Markets / SymbolDetail / Portfolio / PnL / Blotter / Custody / Settings / alerts) or a
 * curated action (new price alert / deposit → custody / trade the saved default symbol). Not the app
 * start destination; reached from the Markets header search icon and the More hub.
 */
data object GlobalSearchDest {
    const val ROUTE = "search"
}

/** Registers the global search screen, mapping each [SearchDest] + action to an existing route. */
fun NavGraphBuilder.globalSearchDestination(navController: NavHostController) {
    composable(GlobalSearchDest.ROUTE) { backStackEntry ->
        val viewModel = androidx.hilt.navigation.compose.hiltViewModel<SearchViewModel>(backStackEntry)
        GlobalSearchRoute(
            onBack = { navController.popBackStack() },
            onOpenSymbol = { symbolId ->
                navController.navigate(SymbolDetailDest.build(symbolId)) { launchSingleTop = true }
            },
            onOpenDestination = { dest ->
                navController.navigate(routeFor(dest)) { launchSingleTop = true }
            },
            onRunAction = { action ->
                val route = when (action) {
                    SearchActionId.NEW_PRICE_ALERT -> PriceAlertsDest.ROUTE
                    // Funding surface (custody deposit) — mirrors HomeTarget.DEPOSIT.
                    SearchActionId.DEPOSIT -> CustodyDest.ROUTE
                    // Order entry lives on the per-symbol detail; open the saved default, else the list.
                    SearchActionId.TRADE_DEFAULT_SYMBOL ->
                        viewModel.defaultSymbolId()?.let { SymbolDetailDest.build(it) } ?: MarketsDest.ROUTE
                }
                navController.navigate(route) { launchSingleTop = true }
            },
            viewModel = viewModel,
        )
    }
}

/** Map a [SearchDest] to its concrete existing authenticated-graph route. */
private fun routeFor(dest: SearchDest): String = when (dest) {
    SearchDest.HOME -> HomeDest.ROUTE
    SearchDest.MARKETS -> MarketsDest.ROUTE
    // Portfolio aggregates the staking snapshot; there is no standalone staking route.
    SearchDest.PORTFOLIO, SearchDest.STAKING -> PortfolioDest.ROUTE
    SearchDest.PNL -> PnlDest.ROUTE
    SearchDest.BLOTTER -> BlotterDest.ROUTE
    SearchDest.CUSTODY -> CustodyDest.ROUTE
    SearchDest.SETTINGS -> MainDest.SettingsTrading.route
    SearchDest.PRICE_ALERTS -> PriceAlertsDest.ROUTE
    SearchDest.TRADING_ALERTS -> TradingAlertsDest.ROUTE
}
