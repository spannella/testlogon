package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.stories.StoryViewerRoute
import com.testlogon.android.feature.stories.StoryViewerViewModel

/**
 * AND-199 / AND-200 — full-screen story viewer route `stories/viewer/{userId}`, keyed by the author
 * (web parity: the tray passes entry.user_id into the viewer). The ViewModel resolves the tray list to
 * advance across authors and fetches the author's segments lazily.
 */
data object StoryViewerDest {
    const val ROUTE = "stories/viewer/{${StoryViewerViewModel.ARG_USER_ID}}"

    fun build(userId: String): String = "stories/viewer/${Uri.encode(userId)}"
}

/** AND-199 — registers the story viewer destination. Close + back both pop to the prior route. */
fun NavGraphBuilder.storyViewerDestination(navController: NavHostController) {
    composable(
        route = StoryViewerDest.ROUTE,
        arguments = listOf(
            navArgument(StoryViewerViewModel.ARG_USER_ID) { type = NavType.StringType },
        ),
    ) {
        StoryViewerRoute(
            onDismiss = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.AUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}
