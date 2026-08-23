package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.watchlist.WatchlistRoute

/**
 * UNIFIED Watchlist destination, registered in the AUTHENTICATED nav graph.
 *
 * [WatchlistDest] is the single list of every starred item across exchange symbols, creator tokens,
 * and strategy funds. It owns no detail routes: each row deep-links (via the route string the
 * view-model computes) back into the existing per-product detail destinations in this same graph.
 */
data object WatchlistDest {
    const val ROUTE = "watchlist"
}

/** Registers the unified Watchlist list destination (Back pops the back stack). */
fun NavGraphBuilder.watchlistDestination(navController: NavHostController) {
    composable(WatchlistDest.ROUTE) {
        WatchlistRoute(
            onBack = { navController.popBackStack() },
            onOpen = { route -> navController.navigate(route) { launchSingleTop = true } },
        )
    }
}
