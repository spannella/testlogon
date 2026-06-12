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
import com.testlogon.android.feature.broadcast.host.IngestRoute
import com.testlogon.android.feature.broadcast.host.IngestViewModel
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
    ) {
        IngestRoute(onBack = { navController.popBackStack() })
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
