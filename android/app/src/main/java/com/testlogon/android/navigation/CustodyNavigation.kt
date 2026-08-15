package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.custody.CustodyRoute

/** The native Custody surface (balances / deposit / withdraw / activity / officer approvals), reached from the More -> Wallet hub. */
data object CustodyDest {
    const val ROUTE = "custody"
}

/**
 * Registers the Custody screen in the authenticated graph. Up / Back pops the back stack. The screen
 * is wired to the session-authed the /ui/custody endpoints backend (the shared Retrofit client attaches the cookie);
 * the officer Approvals/Audit tab self-gates on the caller's admin signal.
 */
fun NavGraphBuilder.custodyDestination(navController: NavHostController) {
    composable(CustodyDest.ROUTE) {
        CustodyRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
