package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.markets.MarketsRoute
import com.testlogon.android.feature.markets.SymbolDetailRoute

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

/** Registers the Markets list + per-symbol detail destinations (Back pops the back stack). */
fun NavGraphBuilder.marketsDestinations(navController: NavHostController) {
    composable(MarketsDest.ROUTE) {
        MarketsRoute(
            onBack = { navController.popBackStack() },
            onOpenSymbol = { symbolId ->
                navController.navigate(SymbolDetailDest.build(symbolId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = SymbolDetailDest.ROUTE,
        arguments = listOf(
            navArgument(SymbolDetailDest.ARG_SYMBOL_ID) { type = NavType.IntType },
        ),
    ) {
        SymbolDetailRoute(onBack = { navController.popBackStack() })
    }
}
