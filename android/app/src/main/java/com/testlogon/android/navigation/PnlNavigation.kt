package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.pnl.PnlRoute

/**
 * The read-only PnL & performance surface, reached from the More -> Wallet hub (near Portfolio).
 * Derives realized/unrealized PnL, fees, win rate, an equity curve, and a per-symbol breakdown from
 * the exchange fills-fees / liquidations / funding / margin reads. No order entry, no money movement.
 */
data object PnlDest {
    const val ROUTE = "pnl"
}

/** Registers the PnL screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.pnlDestination(navController: NavHostController) {
    composable(PnlDest.ROUTE) {
        PnlRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
