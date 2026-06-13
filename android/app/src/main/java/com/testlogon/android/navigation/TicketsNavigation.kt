package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.tickets.ui.SpacesListRoute
import com.testlogon.android.feature.tickets.ui.TicketListRoute
import com.testlogon.android.feature.tickets.ui.TicketThreadRoute

/**
 * AND-372 - the READ-ONLY ticket-spaces destinations: a SPACES list -> a space's TICKET list (Paging-3) -> a
 * ticket THREAD (embedded messages). Each ViewModel reads its nav args ({spaceId} / {ticketId}) from
 * SavedStateHandle. Composing / replying / member or status edits are AND-373 and OUT OF SCOPE.
 */
data object TicketSpacesListDest {
    const val ROUTE = "tickets/spaces"
}

data object TicketListDest {
    const val ARG_SPACE_ID = "spaceId"
    const val ROUTE = "tickets/space/{$ARG_SPACE_ID}"

    fun build(spaceId: String): String = "tickets/space/${Uri.encode(spaceId)}"
}

data object TicketThreadDest {
    const val ARG_SPACE_ID = "spaceId"
    const val ARG_TICKET_ID = "ticketId"
    const val ROUTE = "tickets/space/{$ARG_SPACE_ID}/ticket/{$ARG_TICKET_ID}"

    fun build(spaceId: String, ticketId: String): String =
        "tickets/space/${Uri.encode(spaceId)}/ticket/${Uri.encode(ticketId)}"
}

/**
 * AND-372 - registers the spaces -> tickets -> thread destinations in the authenticated graph (one shared nav
 * graph; NOT forked). Each screen's one-shot NavigateToLogin effect (a TERMINAL 401) routes to the login /
 * unauthenticated graph carrying [LogoutReason.SESSION_EXPIRED] (mirrors the existing re-auth handoff); the
 * AND-022/025 auth gate then keeps the user there once the session flips unauthenticated.
 */
fun NavGraphBuilder.ticketsDestinations(navController: NavHostController) {
    composable(route = TicketSpacesListDest.ROUTE) {
        SpacesListRoute(
            onBack = { navController.popBackStack() },
            onOpenSpace = { spaceId ->
                navController.navigate(TicketListDest.build(spaceId)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToTicketsReauth() },
        )
    }
    composable(
        route = TicketListDest.ROUTE,
        arguments = listOf(
            navArgument(TicketListDest.ARG_SPACE_ID) { type = NavType.StringType },
        ),
    ) {
        TicketListRoute(
            onBack = { navController.popBackStack() },
            onOpenTicket = { ticketId ->
                val spaceId = it.arguments?.getString(TicketListDest.ARG_SPACE_ID).orEmpty()
                navController.navigate(TicketThreadDest.build(spaceId, ticketId)) {
                    launchSingleTop = true
                }
            },
            onNavigateToLogin = { navController.navigateToTicketsReauth() },
        )
    }
    composable(
        route = TicketThreadDest.ROUTE,
        arguments = listOf(
            navArgument(TicketThreadDest.ARG_SPACE_ID) { type = NavType.StringType },
            navArgument(TicketThreadDest.ARG_TICKET_ID) { type = NavType.StringType },
        ),
    ) {
        TicketThreadRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToTicketsReauth() },
        )
    }
}

/**
 * AND-372 - the terminal-401 re-auth handoff: navigate to the Login destination carrying the SESSION_EXPIRED
 * reason. Login lives in the unauthenticated graph registered in the same NavHost, so this is reachable
 * directly; the auth gate (AppNavHost) finishes clearing the back stack once auth flips.
 */
private fun NavHostController.navigateToTicketsReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
