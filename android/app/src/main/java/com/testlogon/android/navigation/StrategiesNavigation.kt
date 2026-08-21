package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.strategies.StrategyBuilderRoute
import com.testlogon.android.feature.strategies.StrategyDetailRoute
import com.testlogon.android.feature.strategies.StrategyMarketRoute
import com.testlogon.android.feature.strategies.StrategyPaperRoute

/**
 * USER-CREATED STRATEGIES / BASKETS (investable funds) destinations, registered in the AUTHENTICATED
 * nav graph.
 *
 * [StrategyMarketDest] is the marketplace + "my strategies" list (the navigable hub entry);
 * [StrategyBuilderDest] is the create/edit form (id = "new" for a fresh draft); [StrategyDetailDest]
 * is the per-strategy detail + invest/redeem; [StrategyPaperDest] is the paper-run + backtest screen.
 * All read surfaces degrade to honest empty/pending states when the (not-yet-built) `me/strategies/(all)`
 * backend 404s.
 */
data object StrategyMarketDest {
    const val ROUTE = "strategies"
}

data object StrategyBuilderDest {
    const val ROUTE = "strategies/builder/{strategyId}"
    const val ARG_STRATEGY_ID = "strategyId"

    /** Sentinel id for a brand-new draft (no strategy loaded for edit). */
    const val NEW = "new"

    fun build(strategyId: String): String = "strategies/builder/${Uri.encode(strategyId)}"
    fun buildNew(): String = build(NEW)
}

data object StrategyDetailDest {
    const val ROUTE = "strategies/detail/{strategyId}"
    const val ARG_STRATEGY_ID = "strategyId"

    fun build(strategyId: String): String = "strategies/detail/${Uri.encode(strategyId)}"
}

data object StrategyPaperDest {
    const val ROUTE = "strategies/paper/{strategyId}"
    const val ARG_STRATEGY_ID = "strategyId"

    fun build(strategyId: String): String = "strategies/paper/${Uri.encode(strategyId)}"
}

/** Registers the strategy marketplace + builder + detail + paper-run destinations (Back pops the stack). */
fun NavGraphBuilder.strategiesDestinations(navController: NavHostController) {
    composable(StrategyMarketDest.ROUTE) {
        StrategyMarketRoute(
            onBack = { navController.popBackStack() },
            onOpenStrategy = { id -> navController.navigate(StrategyDetailDest.build(id)) { launchSingleTop = true } },
            onCreate = { navController.navigate(StrategyBuilderDest.buildNew()) { launchSingleTop = true } },
        )
    }
    composable(
        route = StrategyBuilderDest.ROUTE,
        arguments = listOf(navArgument(StrategyBuilderDest.ARG_STRATEGY_ID) { type = NavType.StringType }),
    ) {
        StrategyBuilderRoute(
            onBack = { navController.popBackStack() },
            onSaved = { id ->
                // Replace the builder with the saved strategy's detail so Back returns to the list.
                navController.navigate(StrategyDetailDest.build(id)) {
                    launchSingleTop = true
                    popUpTo(StrategyBuilderDest.ROUTE) { inclusive = true }
                }
            },
        )
    }
    composable(
        route = StrategyDetailDest.ROUTE,
        arguments = listOf(navArgument(StrategyDetailDest.ARG_STRATEGY_ID) { type = NavType.StringType }),
    ) {
        StrategyDetailRoute(
            onBack = { navController.popBackStack() },
            onEdit = { id -> navController.navigate(StrategyBuilderDest.build(id)) { launchSingleTop = true } },
            onPaperRun = { id -> navController.navigate(StrategyPaperDest.build(id)) { launchSingleTop = true } },
        )
    }
    composable(
        route = StrategyPaperDest.ROUTE,
        arguments = listOf(navArgument(StrategyPaperDest.ARG_STRATEGY_ID) { type = NavType.StringType }),
    ) {
        StrategyPaperRoute(onBack = { navController.popBackStack() })
    }
}
