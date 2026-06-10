package com.testlogon.android.feature.messaging.nav

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.messaging.contacts.ContactsRoute
import com.testlogon.android.feature.messaging.dm.StartDmRoute
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.feature.messaging.helpdesk.HelpdeskDetailRoute
import com.testlogon.android.feature.messaging.helpdesk.HelpdeskDetailViewModel
import com.testlogon.android.feature.messaging.helpdesk.HelpdeskQueueRoute
import com.testlogon.android.feature.messaging.mass.MassMessagesRoute as MassMessagesScreenRoute
import com.testlogon.android.feature.messaging.groupcreate.GroupCreateRoute
import com.testlogon.android.feature.messaging.groupdetails.GroupDetailsRoute
import com.testlogon.android.feature.messaging.groupsettings.GroupSettingsRoute
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

    /** AND-157 — group-create flow (pick members + name -> create -> open the new thread). */
    const val GROUP_CREATE = "messaging/group/create"

    /** AND-158/AND-159 — per-conversation arg shared by the group details + settings routes. */
    const val ARG_CONVERSATION_ID = "conversationId"

    /** AND-158 — group details / participants management. */
    const val GROUP_DETAILS = "messaging/group/details/{$ARG_CONVERSATION_ID}"

    /** AND-159 — group settings (mute / leave / accept). */
    const val GROUP_SETTINGS = "messaging/group/settings/{$ARG_CONVERSATION_ID}"

    /** AND-160 — mass messages (broadcast campaigns) list + create sheet. */
    const val MASS_MESSAGES = "messaging/mass"

    /** AND-161 — agent-facing helpdesk queue. */
    const val HELPDESK_QUEUE = "messaging/helpdesk/queue"

    /** AND-162 — helpdesk conversation detail (claim + reply). Carries the row's claim state. */
    const val ARG_CLAIM_STATE = HelpdeskDetailViewModel.ARG_CLAIM_STATE
    const val HELPDESK_DETAIL =
        "messaging/helpdesk/conversation/{$ARG_CONVERSATION_ID}?$ARG_CLAIM_STATE={$ARG_CLAIM_STATE}"

    fun helpdeskDetail(conversationId: String, claimStateArg: String): String =
        "messaging/helpdesk/conversation/${Uri.encode(conversationId)}?$ARG_CLAIM_STATE=${Uri.encode(claimStateArg)}"

    fun groupDetails(conversationId: String): String =
        "messaging/group/details/${Uri.encode(conversationId)}"

    fun groupSettings(conversationId: String): String =
        "messaging/group/settings/${Uri.encode(conversationId)}"

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
            onNewGroup = {
                navController.navigate(MessagingRoutes.GROUP_CREATE) { launchSingleTop = true }
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
    ) { entry ->
        val conversationId =
            entry.arguments?.getString(ThreadViewModel.ARG_CONVERSATION_ID).orEmpty()
        ThreadRoute(
            onBack = { navController.popBackStack() },
            onOpenGroupDetails = {
                if (conversationId.isNotBlank()) {
                    navController.navigate(MessagingRoutes.groupDetails(conversationId)) {
                        launchSingleTop = true
                    }
                }
            },
        )
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
    // AND-157 — group create. On success open the new thread and pop the create form off the stack.
    composable(MessagingRoutes.GROUP_CREATE) {
        GroupCreateRoute(
            onGroupCreated = { conversationId ->
                navController.navigate(MessagingRoutes.thread(conversationId)) {
                    popUpTo(MessagingRoutes.GROUP_CREATE) { inclusive = true }
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
    // AND-158 — group details / participants management.
    composable(
        route = MessagingRoutes.GROUP_DETAILS,
        arguments = listOf(
            navArgument(MessagingRoutes.ARG_CONVERSATION_ID) { type = NavType.StringType },
        ),
    ) { entry ->
        val conversationId =
            entry.arguments?.getString(MessagingRoutes.ARG_CONVERSATION_ID).orEmpty()
        GroupDetailsRoute(
            onBack = { navController.popBackStack() },
            onOpenSettings = {
                if (conversationId.isNotBlank()) {
                    navController.navigate(MessagingRoutes.groupSettings(conversationId)) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
    // AND-159 — group settings (mute / leave / accept).
    composable(
        route = MessagingRoutes.GROUP_SETTINGS,
        arguments = listOf(
            navArgument(MessagingRoutes.ARG_CONVERSATION_ID) { type = NavType.StringType },
        ),
    ) {
        GroupSettingsRoute(
            onLeftGroup = {
                // Leaving returns to the conversation list, popping the settings + thread.
                navController.popBackStack(MessagingRoutes.LIST, inclusive = false)
            },
            onBack = { navController.popBackStack() },
        )
    }
    // AND-160 — mass messages (broadcast campaigns). Self-gates on the mass-send capability.
    composable(MessagingRoutes.MASS_MESSAGES) {
        MassMessagesScreenRoute(onBack = { navController.popBackStack() })
    }
    // AND-161 — helpdesk queue. Row tap opens the AND-162 detail (claim + reply).
    composable(MessagingRoutes.HELPDESK_QUEUE) {
        HelpdeskQueueRoute(
            onOpenConversation = { conversationId, claimState ->
                navController.navigate(
                    MessagingRoutes.helpdeskDetail(
                        conversationId = conversationId,
                        claimStateArg = HelpdeskDetailViewModel.encodeAssignment(claimState.toAssignment()),
                    ),
                ) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    // AND-162 — helpdesk conversation detail (claim + reply).
    composable(
        route = MessagingRoutes.HELPDESK_DETAIL,
        arguments = listOf(
            navArgument(MessagingRoutes.ARG_CONVERSATION_ID) { type = NavType.StringType },
            navArgument(MessagingRoutes.ARG_CLAIM_STATE) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        HelpdeskDetailRoute(
            onBack = { navController.popBackStack() },
        )
    }
}

/** AND-162 — map the queue row's [ClaimState] to the detail's initial assignment. */
private fun ClaimState.toAssignment(): com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment =
    when (this) {
        ClaimState.UNASSIGNED -> com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment.UNCLAIMED
        ClaimState.CLAIMED_BY_ME -> com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment.ASSIGNED_TO_ME
        ClaimState.CLAIMED_BY_OTHER -> com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment.ASSIGNED_TO_OTHER
    }
