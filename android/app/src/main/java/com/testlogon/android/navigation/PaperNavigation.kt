package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.paper.PaperRoute

/**
 * The self-contained PAPER TRADING surface, reached from the More -> Wallet hub. A client-side
 * simulation: an isolated paper account (starting balance + positions + orders + fills + PnL) driven by
 * the pure PaperEngine, fed live market-data marks so limit orders fill as the market moves. It NEVER
 * touches the real order/matching stack — no real order is ever placed.
 */
data object PaperDest {
    const val ROUTE = "paper/trade"
}

/** Registers the Paper Trading screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.paperDestination(navController: NavHostController) {
    composable(PaperDest.ROUTE) {
        PaperRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
