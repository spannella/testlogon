package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.markets.MarketsRoute
import com.testlogon.android.feature.markets.SymbolDetailRoute
import com.testlogon.android.feature.markets.alerts.TradingAlertsRoute
import com.testlogon.android.feature.markets.alerts.pricealerts.PriceAlertsRoute
import com.testlogon.android.feature.analysis.MarketAnalysisRoute
import com.testlogon.android.feature.activity.ActivityCenterRoute

/**
 * Markets (exchange market-data, VIEW-ONLY) destinations, registered in the AUTHENTICATED nav graph.
 *
 * [MarketsDest] is the instrument list; [SymbolDetailDest] is the per-symbol detail addressed by the
 * numeric symbolId (1=BTCUSDC, 2=ETHUSDC, 3=SOLUSDC). Both are read-only; no order entry.
 */
data object MarketsDest {
    const val ROUTE = "markets"
}

data object SymbolDetailDest {
    const val ROUTE = "markets/{symbolId}"
    const val ARG_SYMBOL_ID = "symbolId"

    fun build(symbolId: Int): String = "markets/$symbolId"
}

/** Trading Alerts (derived notifications) list — reachable from the Markets header bell + More hub. */
data object TradingAlertsDest {
    const val ROUTE = "markets/alerts"
}

/** Price Alerts (user-authored) management — reachable from the Trading Alerts screen. */
data object PriceAlertsDest {
    const val ROUTE = "markets/alerts/price"
}

/** Analysis workbench (historical market-data research/backtest) — a new navigable destination. */
data object AnalysisDest {
    const val ROUTE = "markets/analysis"
}

/** Consolidated Activity Center (durable, day-grouped account-event timeline). New navigable destination. */
data object ActivityCenterDest {
    const val ROUTE = "activity/center"
}

/** Registers the Markets list + per-symbol detail destinations (Back pops the back stack). */
fun NavGraphBuilder.marketsDestinations(navController: NavHostController) {
    composable(MarketsDest.ROUTE) {
        MarketsRoute(
            onBack = { navController.popBackStack() },
            onOpenSymbol = { symbolId ->
                navController.navigate(SymbolDetailDest.build(symbolId)) { launchSingleTop = true }
            },
            onOpenAlerts = {
                navController.navigate(TradingAlertsDest.ROUTE) { launchSingleTop = true }
            },
            onOpenSearch = {
                navController.navigate(GlobalSearchDest.ROUTE) { launchSingleTop = true }
            },
        )
    }
    composable(TradingAlertsDest.ROUTE) {
        TradingAlertsRoute(
            onBack = { navController.popBackStack() },
            onOpenPriceAlerts = {
                navController.navigate(PriceAlertsDest.ROUTE) { launchSingleTop = true }
            },
        )
    }
    composable(PriceAlertsDest.ROUTE) {
        PriceAlertsRoute(onBack = { navController.popBackStack() })
    }
    composable(AnalysisDest.ROUTE) {
        MarketAnalysisRoute(onBack = { navController.popBackStack() })
    }
    composable(ActivityCenterDest.ROUTE) {
        ActivityCenterRoute(
            onBack = { navController.popBackStack() },
            onOpenRoute = { route -> navController.navigate(route) { launchSingleTop = true } },
        )
    }
    composable(
        route = SymbolDetailDest.ROUTE,
        arguments = listOf(
            navArgument(SymbolDetailDest.ARG_SYMBOL_ID) { type = NavType.IntType },
        ),
    ) {
        SymbolDetailRoute(
            onBack = { navController.popBackStack() },
            onOpenRoute = { route -> navController.navigate(route) { launchSingleTop = true } },
        )
    }
}
