package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.messaging.nav.MessagingRoutes
import com.testlogon.android.feature.support.ui.CreateTicketRoute
import com.testlogon.android.feature.support.ui.SupportRoute
import com.testlogon.android.feature.support.ui.SupportTicketDetailRoute

/**
 * B-SUP (batch 7) - the role-branched Support destinations. The landing [SupportDest] resolves the caller's
 * admin status (GET /ui/me.is_admin) and renders the USER help experience OR the ADMIN helpdesk queue. From
 * either it can drill into a ticket [SupportTicketDetailDest] (the isAdmin nav arg gates the admin controls);
 * the USER landing also opens the create-ticket form [SupportCreateTicketDest].
 */
data object SupportDest {
    const val ROUTE = "support"
}

data object SupportCreateTicketDest {
    const val ROUTE = "support/create"
}

data object SupportTicketDetailDest {
    const val ARG_TICKET_ID = "ticketId"
    const val ARG_IS_ADMIN = "isAdmin"
    const val ROUTE = "support/ticket/{$ARG_TICKET_ID}?$ARG_IS_ADMIN={$ARG_IS_ADMIN}"

    fun build(ticketId: String, isAdmin: Boolean): String =
        "support/ticket/${Uri.encode(ticketId)}?$ARG_IS_ADMIN=$isAdmin"
}

fun NavGraphBuilder.supportDestinations(navController: NavHostController) {
    composable(route = SupportDest.ROUTE) {
        SupportRoute(
            onBack = { navController.popBackStack() },
            onOpenTicket = { ticketId, isAdmin ->
                navController.navigate(SupportTicketDetailDest.build(ticketId, isAdmin)) { launchSingleTop = true }
            },
            onCreateTicket = {
                navController.navigate(SupportCreateTicketDest.ROUTE) { launchSingleTop = true }
            },
            // B8 #13 — a live-agent helpdesk_bridge conversation opens in the shared messaging thread UI
            // (registered by messagingGraph in the same authenticated NavHost).
            onOpenConversation = { conversationId ->
                navController.navigate(MessagingRoutes.thread(conversationId)) { launchSingleTop = true }
            },
        )
    }
    composable(route = SupportCreateTicketDest.ROUTE) {
        CreateTicketRoute(
            onBack = { navController.popBackStack() },
            onCreated = { ticketId ->
                // Pop the create form, then open the new ticket thread (user view).
                navController.popBackStack()
                navController.navigate(SupportTicketDetailDest.build(ticketId, isAdmin = false)) {
                    launchSingleTop = true
                }
            },
        )
    }
    composable(
        route = SupportTicketDetailDest.ROUTE,
        arguments = listOf(
            navArgument(SupportTicketDetailDest.ARG_TICKET_ID) { type = NavType.StringType },
            navArgument(SupportTicketDetailDest.ARG_IS_ADMIN) {
                type = NavType.BoolType
                defaultValue = false
            },
        ),
    ) {
        SupportTicketDetailRoute(onBack = { navController.popBackStack() })
    }
}
