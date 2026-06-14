package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.account.closure.AccountClosureRoute
import com.testlogon.android.feature.account.closure.AccountReactivateRoute
import com.testlogon.android.feature.account.closure.AccountSuspendRoute

/**
 * AND-387 - the E50 account-lifecycle destinations (closure / suspend / reactivate), entered from the
 * AND-082 Account settings screen. Each is arg-less: the screen freshly fetches `GET ui/account/status` to
 * gate actions (never off stale cache - spec §6). Entering while unauthenticated is handled by the
 * authenticated graph's gate + the AND-027 401 interceptor.
 *
 * On a successful closure or suspend the repository tears down the local session (AND-032), which flips
 * [com.testlogon.android.data.auth.AuthStateStore.isAuthenticated] to false; the [AppNavHost] auth gate then
 * swaps to the unauthenticated graph automatically. The `onClosed`/`onSuspended` callbacks additionally pop
 * this destination so the back stack is clean. Reactivate pops back to Account settings reflecting `active`.
 */
data object AccountClosureDest {
    const val ROUTE = "account/closure"
}

data object AccountSuspendDest {
    const val ROUTE = "account/suspend"
}

data object AccountReactivateDest {
    const val ROUTE = "account/reactivate"
}

fun NavController.navigateToAccountClosure() =
    navigate(AccountClosureDest.ROUTE) { launchSingleTop = true }

fun NavController.navigateToAccountSuspend() =
    navigate(AccountSuspendDest.ROUTE) { launchSingleTop = true }

fun NavController.navigateToAccountReactivate() =
    navigate(AccountReactivateDest.ROUTE) { launchSingleTop = true }

/** AND-387 - registers the closure / suspend / reactivate destinations. */
fun NavGraphBuilder.accountLifecycleDestinations(navController: NavHostController) {
    composable(route = AccountClosureDest.ROUTE) {
        AccountClosureRoute(
            onClosed = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
    composable(route = AccountSuspendDest.ROUTE) {
        AccountSuspendRoute(
            onSuspended = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
    composable(route = AccountReactivateDest.ROUTE) {
        AccountReactivateRoute(
            onReactivated = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
}
