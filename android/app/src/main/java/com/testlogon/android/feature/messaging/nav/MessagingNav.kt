package com.testlogon.android.feature.messaging.nav

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
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

    fun thread(conversationId: String): String =
        "messaging/thread/${Uri.encode(conversationId)}"
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
}
