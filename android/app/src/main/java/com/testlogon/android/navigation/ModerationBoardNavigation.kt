package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.adminmod.BanManagementRoute
import com.testlogon.android.feature.adminmod.ModerationBoardRoute
import com.testlogon.android.feature.adminmod.ModerationDetailArgs
import com.testlogon.android.feature.adminmod.ModerationDetailRoute

/**
 * B5 - the admin content-moderation board (list) + ticket detail, registered in the AUTHENTICATED graph.
 * Role-gated: the ViewModel maps a backend 403 to the Forbidden state (defense in depth; content reports fold
 * into these tickets). Mirrors the web /admin/moderation page.
 */
data object ModerationBoardDest {
    const val ROUTE = "admin/moderation"
}

data object ModerationTicketDest {
    const val ARG_TICKET_ID = ModerationDetailArgs.TICKET_ID
    const val ROUTE = "admin/moderation/{$ARG_TICKET_ID}"

    fun build(ticketId: String): String = "admin/moderation/${Uri.encode(ticketId)}"
}

/** MODX-19: the ban-management roster, reachable from the board top bar. */
data object ModerationBansDest {
    const val ROUTE = "admin/moderation-bans"
}

fun NavGraphBuilder.moderationBoardDestinations(navController: NavHostController) {
    composable(ModerationBoardDest.ROUTE) {
        ModerationBoardRoute(
            onBack = { navController.popBackStack() },
            onOpenTicket = { ticketId ->
                navController.navigate(ModerationTicketDest.build(ticketId)) { launchSingleTop = true }
            },
            onOpenBans = {
                navController.navigate(ModerationBansDest.ROUTE) { launchSingleTop = true }
            },
        )
    }
    composable(ModerationBansDest.ROUTE) {
        BanManagementRoute(onBack = { navController.popBackStack() })
    }
    composable(
        route = ModerationTicketDest.ROUTE,
        arguments = listOf(navArgument(ModerationTicketDest.ARG_TICKET_ID) { type = NavType.StringType }),
    ) {
        ModerationDetailRoute(onBack = { navController.popBackStack() })
    }
}
