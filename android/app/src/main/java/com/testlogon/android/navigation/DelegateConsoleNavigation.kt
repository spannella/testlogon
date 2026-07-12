package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.delegates.ui.DelegateConsoleRoute
import com.testlogon.android.feature.messaging.nav.MessagingRoutes

/**
 * AND-360 - the delegate console route (the focused manage-as-creator demonstration). Reached from the
 * More hub; the screen self-gates on the managed-creator state (it shows an enter prompt when not in
 * delegate mode) and renders the persistent banner + the gated feed / messaging affordances.
 */
data object DelegateConsoleDest {
    const val ROUTE = "delegate/console"
}

/** AND-360 - registers the delegate console destination in the authenticated graph. */
fun NavGraphBuilder.delegateConsoleDestination(navController: NavHostController) {
    composable(DelegateConsoleDest.ROUTE) {
        DelegateConsoleRoute(
            onBack = { navController.popBackStack() },
            // FULL-PARITY: open the reused full messaging thread + composer for the managed creator's
            // conversation. The delegate context is active (managing-creator), so DelegateRoutingInterceptor
            // re-targets every send/read to the creator-attributed delegate endpoints.
            onOpenThread = { conversationId ->
                navController.navigate(MessagingRoutes.thread(conversationId)) { launchSingleTop = true }
            },
        )
    }
}
