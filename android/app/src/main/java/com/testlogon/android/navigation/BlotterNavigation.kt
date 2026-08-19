package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.blotter.TradingBlotterRoute

/** The native Trading Blotter surface (orders / fills / positions), reached from the More → Studio hub. */
data object BlotterDest {
    const val ROUTE = "trading/blotter"
}

/**
 * Registers the Trading Blotter screen in the authenticated graph. Up / Back pops the back stack.
 * The screen is self-contained (locally generated sample data + a live ticker) — no backend wiring —
 * mirroring the web trading blotter for parity.
 */
fun NavGraphBuilder.blotterDestination(navController: NavHostController) {
    composable(BlotterDest.ROUTE) {
        TradingBlotterRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
