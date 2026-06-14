package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.webhooks.ui.CreateWebhookRoute
import com.testlogon.android.feature.webhooks.ui.WebhookDetailRoute
import com.testlogon.android.feature.webhooks.ui.WebhookDetailViewModel
import com.testlogon.android.feature.webhooks.ui.WebhooksListRoute

/**
 * AND-398 - the WEBHOOKS config (light) destinations: a LIST -> a webhook DETAIL -> a LIGHT CREATE. The detail
 * ViewModel reads its {webhookId} nav arg from SavedStateHandle. Update / delete / rotate / deliveries are FR-6
 * out-of-scope (a future heavyweight ticket).
 */
data object WebhooksListDest {
    const val ROUTE = "webhooks"
}

data object WebhookDetailDest {
    const val ARG_WEBHOOK_ID = WebhookDetailViewModel.ARG_WEBHOOK_ID
    const val ROUTE = "webhooks/detail/{$ARG_WEBHOOK_ID}"

    fun build(webhookId: String): String = "webhooks/detail/${Uri.encode(webhookId)}"
}

data object WebhookCreateDest {
    const val ROUTE = "webhooks/create"
}

/**
 * AND-398 - registers the list -> detail -> create destinations in the authenticated graph (one shared nav
 * graph; NOT forked). After a successful create the create screen pops back to the list, which refreshes on
 * (re)entry and shows the new endpoint (FR-3 / AC-4). Each screen's one-shot NavigateToLogin effect (a TERMINAL
 * 401) routes to the login / unauthenticated graph carrying [LogoutReason.SESSION_EXPIRED] (the existing re-auth
 * handoff). The one-time signing secret returned on create is intentionally NOT carried through navigation /
 * persisted (AC-7); it is surfaced inline by the create screen before the pop.
 */
fun NavGraphBuilder.webhooksDestinations(navController: NavHostController) {
    composable(route = WebhooksListDest.ROUTE) {
        WebhooksListRoute(
            onBack = { navController.popBackStack() },
            onOpenWebhook = { id ->
                navController.navigate(WebhookDetailDest.build(id)) { launchSingleTop = true }
            },
            onCreate = {
                navController.navigate(WebhookCreateDest.ROUTE) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToWebhooksReauth() },
        )
    }
    composable(
        route = WebhookDetailDest.ROUTE,
        arguments = listOf(
            navArgument(WebhookDetailDest.ARG_WEBHOOK_ID) { type = NavType.StringType },
        ),
    ) {
        WebhookDetailRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToWebhooksReauth() },
        )
    }
    composable(route = WebhookCreateDest.ROUTE) {
        CreateWebhookRoute(
            onBack = { navController.popBackStack() },
            onCreated = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToWebhooksReauth() },
        )
    }
}

/**
 * AND-398 - the terminal-401 re-auth handoff: navigate to the Login destination carrying SESSION_EXPIRED. Login
 * lives in the unauthenticated graph registered in the same NavHost; the auth gate finishes clearing the back
 * stack once auth flips. Mirrors the AND-372 ticketsReauth handoff.
 */
private fun NavHostController.navigateToWebhooksReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
