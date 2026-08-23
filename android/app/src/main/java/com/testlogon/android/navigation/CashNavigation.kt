package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.cash.CashRoute

/**
 * The FIAT (USD) Cash surface (deposit / withdraw the USD wallet used for trading, margin & fees),
 * reached from the More -> Wallet hub. Wired to the SAME /ui/billing/wallet endpoints the web app uses
 * (the shared Retrofit client attaches the session cookie). Reads degrade-on-404 to an honest empty
 * state; deposit/withdraw are behind a money-safety confirm.
 */
data object CashDest {
    const val ROUTE = "cash"
}

/** Registers the Cash screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.cashDestination(navController: NavHostController) {
    composable(CashDest.ROUTE) {
        CashRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
