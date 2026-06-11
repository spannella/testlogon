package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.broadcast.BroadcastBrowseRoute
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

/** AND-279/AND-280 — registers the broadcast browse + viewer destinations. */
fun NavGraphBuilder.broadcastDestinations(navController: NavHostController) {
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
