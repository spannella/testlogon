package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
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
import com.testlogon.android.feature.broadcast.viewer.ViewerScreen
import com.testlogon.android.feature.broadcast.viewer.ViewerViewModel

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
