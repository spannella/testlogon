package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.custody.CustodyRoute
import com.testlogon.android.feature.custody.CustodyProvidersRoute

/** The native Custody surface (balances / deposit / withdraw / activity / officer approvals), reached from the More -> Wallet hub. */
data object CustodyDest {
    const val ROUTE = "custody"
}

/** The external custody-provider surface (Fireblocks / BitGo / internal gateway), reached from Custody. */
data object CustodyProvidersDest {
    const val ROUTE = "custody/providers"
}

/**
 * Registers the Custody screen in the authenticated graph. Up / Back pops the back stack. The screen
 * is wired to the session-authed the /me/custody endpoints backend (the shared Retrofit client attaches the cookie);
 * the officer Approvals/Audit tab self-gates on the caller's admin signal.
 */
fun NavGraphBuilder.custodyDestination(navController: NavHostController) {
    composable(CustodyDest.ROUTE) {
        CustodyRoute(
            onBack = { navController.popBackStack() },
            onOpenProviders = { navController.navigate(CustodyProvidersDest.ROUTE) },
        )
    }
}

/**
 * Registers the external custody-provider screen (provider connect/status + per-vault provider +
 * withdrawal approval). Wired to the me/custody/providers|vaults|withdrawals endpoints; reads degrade
 * on 404 to an honest "provider integration pending backend" state.
 */
fun NavGraphBuilder.custodyProvidersDestination(navController: NavHostController) {
    composable(CustodyProvidersDest.ROUTE) {
        CustodyProvidersRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
