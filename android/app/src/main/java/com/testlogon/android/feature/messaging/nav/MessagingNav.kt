package com.testlogon.android.feature.messaging.nav

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.messaging.contacts.ContactsRoute
import com.testlogon.android.feature.messaging.dm.StartDmRoute
import com.testlogon.android.feature.messaging.list.ConversationListRoute
import com.testlogon.android.feature.messaging.search.GlobalSearchRoute
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

    /** AND-152 — optional deep-link arg: scroll the thread to this message id on open. */
    const val ARG_FOCUS_MESSAGE_ID = ThreadViewModel.ARG_FOCUS_MESSAGE_ID
    const val THREAD =
        "messaging/thread/{${ThreadViewModel.ARG_CONVERSATION_ID}}?$ARG_FOCUS_MESSAGE_ID={$ARG_FOCUS_MESSAGE_ID}"

    /** AND-152 — cross-conversation message search screen. */
    const val SEARCH = "messaging/search"

    /** AND-153/AND-154 — contacts (people-search) screen; tapping a contact opens its DM thread. */
    const val CONTACTS = "messaging/contacts"

    /** AND-127 — start-DM entry: resolves a peer user id to a conversation, then opens the thread. */
    const val ARG_PEER_USER_ID = "peerUserId"
    const val START_DM = "messaging/dm/{$ARG_PEER_USER_ID}"

    fun thread(conversationId: String, focusMessageId: String? = null): String {
        val base = "messaging/thread/${Uri.encode(conversationId)}"
        return if (focusMessageId.isNullOrBlank()) {
            base
        } else {
            "$base?$ARG_FOCUS_MESSAGE_ID=${Uri.encode(focusMessageId)}"
        }
    }

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
            onOpenSearch = {
                navController.navigate(MessagingRoutes.SEARCH) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = MessagingRoutes.THREAD,
        arguments = listOf(
            navArgument(ThreadViewModel.ARG_CONVERSATION_ID) { type = NavType.StringType },
            navArgument(MessagingRoutes.ARG_FOCUS_MESSAGE_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        ThreadRoute(onBack = { navController.popBackStack() })
    }
    composable(MessagingRoutes.SEARCH) {
        GlobalSearchRoute(
            onOpenResult = { conversationId, messageId ->
                navController.navigate(MessagingRoutes.thread(conversationId, focusMessageId = messageId)) {
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(MessagingRoutes.CONTACTS) {
        ContactsRoute(
            onOpenThread = { conversationId ->
                navController.navigate(MessagingRoutes.thread(conversationId)) {
                    launchSingleTop = true // FR-5: don't stack duplicate thread destinations
                }
            },
            onBack = { navController.popBackStack() },
        )
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
