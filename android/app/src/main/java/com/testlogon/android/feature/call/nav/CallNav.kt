package com.testlogon.android.feature.call.nav

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.call.group.GroupCallRoute
import com.testlogon.android.feature.call.group.GroupCallViewModel
import com.testlogon.android.feature.call.history.CallHistoryRoute
import com.testlogon.android.feature.call.incall.InCallRoute
import com.testlogon.android.feature.call.ui.OutgoingCallRoute
import com.testlogon.android.feature.call.ui.OutgoingCallViewModel

/**
 * AND-296 — call navigation routes.
 *
 * The outgoing-call screen is a full-screen destination reached from a thread top bar or a profile
 * "Call" affordance; call history is a full-screen destination reached from the More hub.
 */
object CallRoutes {
    const val HISTORY = "call/history"

    // AND-298 — in-call (1:1) destination, reached once a call is connected.
    const val INCALL = "call/incall/{callId}"

    fun incall(callId: String): String = "call/incall/${Uri.encode(callId)}"

    // AND-299 — group-call destinations. CREATE is keyed by conversationId (a new call is created on
    // entry); JOIN is keyed by an existing callId. Both carry an optional mode.
    const val ARG_GROUP_CONVERSATION_ID = GroupCallViewModel.ARG_CONVERSATION_ID
    const val ARG_GROUP_CALL_ID = GroupCallViewModel.ARG_CALL_ID
    const val ARG_GROUP_MODE = GroupCallViewModel.ARG_MODE

    const val GROUP =
        "call/group/{$ARG_GROUP_CONVERSATION_ID}?$ARG_GROUP_MODE={$ARG_GROUP_MODE}"

    const val GROUP_JOIN =
        "call/group/join/{$ARG_GROUP_CALL_ID}?$ARG_GROUP_MODE={$ARG_GROUP_MODE}"

    fun group(conversationId: String, mode: String = "video"): String =
        "call/group/${Uri.encode(conversationId)}?$ARG_GROUP_MODE=${Uri.encode(mode)}"

    fun groupJoin(callId: String, mode: String = "video"): String =
        "call/group/join/${Uri.encode(callId)}?$ARG_GROUP_MODE=${Uri.encode(mode)}"

    const val ARG_CONVERSATION_ID = OutgoingCallViewModel.ARG_CONVERSATION_ID
    const val ARG_CALLEE_USER_ID = OutgoingCallViewModel.ARG_CALLEE_USER_ID
    const val ARG_MODE = OutgoingCallViewModel.ARG_MODE
    const val ARG_PEER_NAME = OutgoingCallViewModel.ARG_PEER_NAME

    const val OUTGOING =
        "call/outgoing/{$ARG_CONVERSATION_ID}/{$ARG_CALLEE_USER_ID}" +
            "?$ARG_MODE={$ARG_MODE}&$ARG_PEER_NAME={$ARG_PEER_NAME}"

    fun outgoing(
        conversationId: String,
        calleeUserId: String,
        mode: String = "audio",
        peerName: String? = null,
    ): String {
        val base = "call/outgoing/${Uri.encode(conversationId)}/${Uri.encode(calleeUserId)}"
        val name = peerName?.let { "&$ARG_PEER_NAME=${Uri.encode(it)}" }.orEmpty()
        return "$base?$ARG_MODE=${Uri.encode(mode)}$name"
    }
}

/** Registers the outgoing-call + call-history destinations in the authenticated graph. */
fun NavGraphBuilder.callGraph(navController: NavHostController) {
    composable(CallRoutes.HISTORY) {
        CallHistoryRoute(
            onBack = { navController.popBackStack() },
            onCallBack = { /* AND-296 entry: resolving conversation for a redial is upstream. */ },
        )
    }
    composable(
        route = CallRoutes.OUTGOING,
        arguments = listOf(
            navArgument(CallRoutes.ARG_CONVERSATION_ID) { type = NavType.StringType },
            navArgument(CallRoutes.ARG_CALLEE_USER_ID) { type = NavType.StringType },
            navArgument(CallRoutes.ARG_MODE) {
                type = NavType.StringType
                nullable = true
                defaultValue = "audio"
            },
            navArgument(CallRoutes.ARG_PEER_NAME) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        OutgoingCallRoute(onFinished = { navController.popBackStack() })
    }
    composable(
        route = CallRoutes.INCALL,
        arguments = listOf(
            navArgument("callId") { type = NavType.StringType },
        ),
    ) {
        InCallRoute(onCallEnded = { navController.popBackStack() })
    }
    composable(
        route = CallRoutes.GROUP,
        arguments = listOf(
            navArgument(CallRoutes.ARG_GROUP_CONVERSATION_ID) { type = NavType.StringType },
            navArgument(CallRoutes.ARG_GROUP_MODE) {
                type = NavType.StringType
                nullable = true
                defaultValue = "video"
            },
        ),
    ) {
        GroupCallRoute(onCallEnded = { navController.popBackStack() })
    }
    composable(
        route = CallRoutes.GROUP_JOIN,
        arguments = listOf(
            navArgument(CallRoutes.ARG_GROUP_CALL_ID) { type = NavType.StringType },
            navArgument(CallRoutes.ARG_GROUP_MODE) {
                type = NavType.StringType
                nullable = true
                defaultValue = "video"
            },
        ),
    ) {
        GroupCallRoute(onCallEnded = { navController.popBackStack() })
    }
}
