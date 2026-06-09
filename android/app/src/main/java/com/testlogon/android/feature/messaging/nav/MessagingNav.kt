package com.testlogon.android.feature.messaging.nav

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.messaging.dm.StartDmRoute
import com.testlogon.android.feature.messaging.list.ConversationListRoute
import com.testlogon.android.feature.messaging.thread.ThreadRoute
import com.testlogon.android.feature.messaging.thread.ThreadViewModel

/**
 * AND-121..AND-124 — messaging navigation routes.
 *
 * The conversation list is a full-screen outer-graph destination reached from the More hub; the
 * thread is reached by tapping a conversation row.
 */
object MessagingRoutes {
    const val LIST = "messaging/list"
    const val THREAD = "messaging/thread/{${ThreadViewModel.ARG_CONVERSATION_ID}}"

    /** AND-127 — start-DM entry: resolves a peer user id to a conversation, then opens the thread. */
    const val ARG_PEER_USER_ID = "peerUserId"
    const val START_DM = "messaging/dm/{$ARG_PEER_USER_ID}"

    fun thread(conversationId: String): String =
        "messaging/thread/${Uri.encode(conversationId)}"

    fun startDm(peerUserId: String): String =
        "messaging/dm/${Uri.encode(peerUserId)}"
}

/** Registers the conversation list + thread destinations in the authenticated graph. */
fun NavGraphBuilder.messagingGraph(navController: NavHostController) {
    composable(MessagingRoutes.LIST) {
        ConversationListRoute(
            onOpenConversation = { id ->
                navController.navigate(MessagingRoutes.thread(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = MessagingRoutes.THREAD,
        arguments = listOf(
            navArgument(ThreadViewModel.ARG_CONVERSATION_ID) { type = NavType.StringType },
        ),
    ) {
        ThreadRoute(onBack = { navController.popBackStack() })
    }
    composable(
        route = MessagingRoutes.START_DM,
        arguments = listOf(
            navArgument(MessagingRoutes.ARG_PEER_USER_ID) { type = NavType.StringType },
        ),
    ) { entry ->
        val peerUserId =
            requireNotNull(entry.arguments?.getString(MessagingRoutes.ARG_PEER_USER_ID))
        StartDmRoute(
            peerUserId = peerUserId,
            onOpenThread = { conversationId ->
                // Replace the start-DM screen on the back stack so Back returns to the origin.
                navController.navigate(MessagingRoutes.thread(conversationId)) {
                    popUpTo(MessagingRoutes.START_DM) { inclusive = true }
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
