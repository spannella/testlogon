package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.broadcast.BroadcastBrowseRoute
import com.testlogon.android.feature.broadcast.host.CreateBroadcastRoute
import com.testlogon.android.feature.broadcast.host.CreateBroadcastViewModel
import com.testlogon.android.feature.broadcast.host.HostControlRoute
import com.testlogon.android.feature.broadcast.host.HostControlViewModel
import com.testlogon.android.feature.broadcast.host.IngestRoute
import com.testlogon.android.feature.broadcast.host.IngestViewModel
import com.testlogon.android.feature.broadcast.inputs.InputsRoute
import com.testlogon.android.feature.broadcast.inputs.InputsViewModel
import com.testlogon.android.feature.broadcast.layout.LayoutRoute
import com.testlogon.android.feature.broadcast.layout.LayoutViewModel
import com.testlogon.android.feature.broadcast.moderation.ModerationLogRoute
import com.testlogon.android.feature.broadcast.moderation.ModerationViewModel
import com.testlogon.android.feature.broadcasthost.manage.GoalsProductsViewModel
import com.testlogon.android.feature.broadcasthost.manage.ManageRoute
import com.testlogon.android.feature.broadcast.viewer.ViewerScreen
import com.testlogon.android.feature.broadcast.viewer.ViewerViewModel
import com.testlogon.android.feature.guest.GuestAcceptRoute
import com.testlogon.android.feature.guest.GuestAcceptViewModel
import com.testlogon.android.feature.guest.GuestManageRoute
import com.testlogon.android.feature.guest.GuestManageViewModel

/** AND-279 — the broadcast browse (live + scheduled + past) destination. */
data object BroadcastBrowseDest {
    const val ROUTE = "broadcast/browse"
}

/** AND-280 — the viewer playback destination, keyed by sessionId. */
data object BroadcastViewerDest {
    const val ROUTE = "broadcast/viewer/{${ViewerViewModel.ARG_SESSION_ID}}"

    fun build(sessionId: String): String = "broadcast/viewer/${Uri.encode(sessionId)}"
}

/** AND-307 — the host create/schedule (Go Live) destination, keyed by the broadcast profile id. */
data object BroadcastCreateDest {
    const val ROUTE = "broadcast/create/{${CreateBroadcastViewModel.ARG_PROFILE_ID}}"

    fun build(profileId: String): String = "broadcast/create/${Uri.encode(profileId)}"
}

/** AND-308 — the host ingest (camera/mic publish) destination, keyed by sessionId. */
data object BroadcastIngestDest {
    const val ROUTE = "broadcast/ingest/{${IngestViewModel.ARG_SESSION_ID}}"

    fun build(sessionId: String): String = "broadcast/ingest/${Uri.encode(sessionId)}"
}

/** AND-309 — the host LIVE control (start/stop/resume/reschedule + health) destination, keyed by sessionId. */
data object BroadcastHostControlDest {
    const val ROUTE = "broadcast/host/{${HostControlViewModel.ARG_SESSION_ID}}"

    fun build(sessionId: String): String = "broadcast/host/${Uri.encode(sessionId)}"
}

/** AND-310 — the inputs-management (list / activate / make-live) destination, keyed by sessionId. */
data object BroadcastInputsDest {
    const val ROUTE = "broadcast/{${InputsViewModel.ARG_SESSION_ID}}/inputs"

    fun build(sessionId: String): String = "broadcast/${Uri.encode(sessionId)}/inputs"
}

/** AND-311 — the layout-management (mode chooser: single / side_by_side / pip / grid) destination. */
data object BroadcastLayoutDest {
    const val ROUTE = "broadcast/{${LayoutViewModel.ARG_SESSION_ID}}/layout"

    fun build(sessionId: String): String = "broadcast/${Uri.encode(sessionId)}/layout"
}

/** AND-312 — the host guest-management (invite / promote / mute / remove) destination, keyed by sessionId. */
data object BroadcastGuestsDest {
    const val ROUTE = "broadcast/{${GuestManageViewModel.ARG_SESSION_ID}}/guests"

    fun build(sessionId: String): String = "broadcast/${Uri.encode(sessionId)}/guests"
}

/**
 * AND-313 — the chat-moderation log destination, keyed by sessionId + the broadcast's creatorId (delegate
 * routing). ban / unban / pin / unpin / log all live under the delegate prefix, so a creatorId is required;
 * a blank creatorId still resolves the route but the log surface reports it as unavailable.
 */
data object BroadcastModerationLogDest {
    const val ROUTE =
        "broadcast/{${ModerationViewModel.ARG_SESSION_ID}}/moderation-log" +
            "?${ModerationViewModel.ARG_CREATOR_ID}={${ModerationViewModel.ARG_CREATOR_ID}}"

    fun build(sessionId: String, creatorId: String): String =
        "broadcast/${Uri.encode(sessionId)}/moderation-log" +
            "?${ModerationViewModel.ARG_CREATOR_ID}=${Uri.encode(creatorId)}"
}

/** AND-314 — the host goals + products authoring destination (two tabs), keyed by sessionId. */
data object BroadcastManageDest {
    const val ROUTE = "broadcast/{${GoalsProductsViewModel.ARG_SESSION_ID}}/manage"

    fun build(sessionId: String): String = "broadcast/${Uri.encode(sessionId)}/manage"
}

/**
 * AND-312 — the guest ACCEPT destination, reached from the testlogon://guest/accept deep link. Identity is
 * (sessionId, inviteId) carried as query args (NOT a token). Registered in both top-level graphs so an invite
 * link resolves whether or not the recipient is already signed in.
 */
data object GuestAcceptDest {
    const val ROUTE =
        "guest/accept?${GuestAcceptViewModel.ARG_SESSION_ID}={${GuestAcceptViewModel.ARG_SESSION_ID}}" +
            "&${GuestAcceptViewModel.ARG_INVITE_ID}={${GuestAcceptViewModel.ARG_INVITE_ID}}"

    fun build(sessionId: String, inviteId: String): String =
        "guest/accept?${GuestAcceptViewModel.ARG_SESSION_ID}=${Uri.encode(sessionId)}" +
            "&${GuestAcceptViewModel.ARG_INVITE_ID}=${Uri.encode(inviteId)}"

    /**
     * Deep links for testlogon://guest/accept. The sessionId + inviteId arrive as query params
     * (?sessionId=...&inviteId=...) so they bind to the route's nav args; there is NO token.
     */
    fun deepLinks(): List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "testlogon://guest/accept?" +
                "${GuestAcceptViewModel.ARG_SESSION_ID}={${GuestAcceptViewModel.ARG_SESSION_ID}}" +
                "&${GuestAcceptViewModel.ARG_INVITE_ID}={${GuestAcceptViewModel.ARG_INVITE_ID}}"
        },
    )
}

/** AND-279/AND-280/AND-307 — registers the broadcast browse + viewer + host create destinations. */
fun NavGraphBuilder.broadcastDestinations(navController: NavHostController) {
    composable(
        route = BroadcastCreateDest.ROUTE,
        arguments = listOf(
            navArgument(CreateBroadcastViewModel.ARG_PROFILE_ID) { type = NavType.StringType },
        ),
    ) {
        CreateBroadcastRoute(
            onFinished = { navController.popBackStack() },
            // AND-308 — once the session exists, advance to the ingest (camera/mic publish) screen,
            // replacing the create destination so Back returns to the host.
            onSessionReady = { sessionId ->
                navController.navigate(BroadcastIngestDest.build(sessionId)) {
                    popUpTo(BroadcastCreateDest.ROUTE) { inclusive = true }
                    launchSingleTop = true
                }
            },
        )
    }
    composable(
        route = BroadcastIngestDest.ROUTE,
        arguments = listOf(
            navArgument(IngestViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) { entry ->
        val sessionId = entry.arguments?.getString(IngestViewModel.ARG_SESSION_ID).orEmpty()
        IngestRoute(
            onBack = { navController.popBackStack() },
            // AND-309 — once publishing has started, the host can open the LIVE control surface.
            onHostControls = {
                navController.navigate(BroadcastHostControlDest.build(sessionId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = BroadcastHostControlDest.ROUTE,
        arguments = listOf(
            navArgument(HostControlViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) { entry ->
        val sessionId = entry.arguments?.getString(HostControlViewModel.ARG_SESSION_ID).orEmpty()
        HostControlRoute(
            onBack = { navController.popBackStack() },
            // AND-310 — the host can manage this broadcast's inputs (list / activate / make-live).
            onManageInputs = {
                navController.navigate(BroadcastInputsDest.build(sessionId)) { launchSingleTop = true }
            },
            // AND-311 — the host can manage this broadcast's composition layout (mode chooser).
            onManageLayout = {
                navController.navigate(BroadcastLayoutDest.build(sessionId)) { launchSingleTop = true }
            },
            // AND-312 — the host can manage this broadcast's co-broadcast guests (invite / promote / remove).
            onManageGuests = {
                navController.navigate(BroadcastGuestsDest.build(sessionId)) { launchSingleTop = true }
            },
            // AND-313 — the host can moderate this broadcast's chat + view the moderation log. The creator id
            // (delegate routing) comes from the loaded session's createdBy; blank falls back to host-only.
            onModeration = { creatorId ->
                navController.navigate(BroadcastModerationLogDest.build(sessionId, creatorId)) {
                    launchSingleTop = true
                }
            },
            // AND-314 — the host can author this broadcast's tip goals + featured products.
            onManageGoalsProducts = {
                navController.navigate(BroadcastManageDest.build(sessionId)) { launchSingleTop = true }
            },
        )
    }
    // AND-310 — the inputs-management destination (list inputs, activate/deactivate, promote to program).
    composable(
        route = BroadcastInputsDest.ROUTE,
        arguments = listOf(
            navArgument(InputsViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) {
        InputsRoute(onBack = { navController.popBackStack() })
    }
    // AND-311 — the layout-management destination (choose the broadcast composition mode).
    composable(
        route = BroadcastLayoutDest.ROUTE,
        arguments = listOf(
            navArgument(LayoutViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) {
        LayoutRoute(onBack = { navController.popBackStack() })
    }
    // AND-312 — the host guest-management destination (invite / promote / mute / remove).
    composable(
        route = BroadcastGuestsDest.ROUTE,
        arguments = listOf(
            navArgument(GuestManageViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) {
        GuestManageRoute(onBack = { navController.popBackStack() })
    }
    // AND-313 — the chat-moderation log destination (mute / ban / delete / pin actions + the log + unban).
    composable(
        route = BroadcastModerationLogDest.ROUTE,
        arguments = listOf(
            navArgument(ModerationViewModel.ARG_SESSION_ID) { type = NavType.StringType },
            navArgument(ModerationViewModel.ARG_CREATOR_ID) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
    ) {
        ModerationLogRoute(onBack = { navController.popBackStack() })
    }
    // AND-314 — the host goals + products authoring destination (two tabs).
    composable(
        route = BroadcastManageDest.ROUTE,
        arguments = listOf(
            navArgument(GoalsProductsViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) {
        ManageRoute(onBack = { navController.popBackStack() })
    }
    composable(BroadcastBrowseDest.ROUTE) {
        BroadcastBrowseRoute(
            onBack = { navController.popBackStack() },
            onSessionClick = { sessionId, _ ->
                navController.navigate(BroadcastViewerDest.build(sessionId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = BroadcastViewerDest.ROUTE,
        arguments = listOf(
            navArgument(ViewerViewModel.ARG_SESSION_ID) { type = NavType.StringType },
        ),
    ) {
        ViewerScreen(
            onBack = { navController.popBackStack() },
            // AND-283 — Buy from the products shelf routes to the AND-206 product detail.
            onBuyProduct = { categoryId, itemId ->
                navController.navigate(ProductDetailDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
        )
    }
}

/**
 * AND-312 — registers the guest ACCEPT destination + its testlogon://guest/accept deep link. Registered in
 * BOTH top-level graphs (an invitee may not be signed in), mirroring [publicClipDestination]. On a cold
 * deep-link start the back stack may be empty; Done falls back to the graph start.
 */
fun NavGraphBuilder.guestAcceptDestination(navController: NavHostController) {
    composable(
        route = GuestAcceptDest.ROUTE,
        arguments = listOf(
            navArgument(GuestAcceptViewModel.ARG_SESSION_ID) {
                type = NavType.StringType
                defaultValue = ""
            },
            navArgument(GuestAcceptViewModel.ARG_INVITE_ID) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
        deepLinks = GuestAcceptDest.deepLinks(),
    ) {
        GuestAcceptRoute(
            onDone = {
                if (!navController.popBackStack()) {
                    navController.navigate(
                        navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED,
                    ) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}
