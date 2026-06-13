package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.privacy.deletion.AccountDeletionRoute

/**
 * AND-386 - the account-deletion destination (Settings -> Privacy -> Delete account). Arg-less: the screen
 * reads the authenticated user's deletion state from GET /ui/privacy/account-deletion/requests and drives the
 * request/cancel mutations. Entering while unauthenticated is handled by the authenticated graph's gate + the
 * AND-027 401 interceptor.
 */
data object AccountDeletionDest {
    const val ROUTE = "privacy_account_deletion"
}

/** AND-386 - navigation seam used by the Privacy entry row. */
fun NavController.navigateToAccountDeletion() {
    navigate(AccountDeletionDest.ROUTE) { launchSingleTop = true }
}

/** AND-386 - registers the `privacy_account_deletion` destination. */
fun NavGraphBuilder.accountDeletionDestination(navController: NavHostController) {
    composable(route = AccountDeletionDest.ROUTE) {
        AccountDeletionRoute(onBack = { navController.popBackStack() })
    }
}
