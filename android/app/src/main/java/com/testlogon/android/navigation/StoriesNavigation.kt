package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.stories.CreateStoryRoute
import com.testlogon.android.feature.stories.HighlightsRoute
import com.testlogon.android.feature.stories.HighlightsViewModel
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

/**
 * PAR-01 — create-a-story route `stories/create`, launched from the "Your story" tray tile. Pops back on
 * a successful post (the tray then refreshes so the author's own ring appears).
 */
data object CreateStoryDest {
    const val ROUTE = "stories/create"

    fun build(): String = ROUTE
}

/** PAR-01 — registers the create-story destination. Back + a successful post both pop to the feed. */
fun NavGraphBuilder.createStoryDestination(navController: NavHostController) {
    composable(route = CreateStoryDest.ROUTE) {
        CreateStoryRoute(onBack = { navController.popBackStack() })
    }
}

/**
 * PAR-16 - Story Highlights route `stories/highlights/{userId}`. Opened from a profile: the OWN profile
 * passes the [HighlightsViewModel.ARG_ME] sentinel (owner mode), a public profile passes the creator id
 * (read-only unless it resolves to the signed-in user). Back pops to the profile.
 */
data object HighlightsDest {
    const val ROUTE = "stories/highlights/{${HighlightsViewModel.ARG_USER_ID}}"

    fun build(userId: String): String = "stories/highlights/${Uri.encode(userId)}"

    /** Convenience for the OWN profile (the app does not know its own sub client-side). */
    fun buildForSelf(): String = build(HighlightsViewModel.ARG_ME)
}

/** PAR-16 - registers the Story Highlights destination. */
fun NavGraphBuilder.highlightsDestination(navController: NavHostController) {
    composable(
        route = HighlightsDest.ROUTE,
        arguments = listOf(
            navArgument(HighlightsViewModel.ARG_USER_ID) { type = NavType.StringType },
        ),
    ) {
        HighlightsRoute(onBack = { navController.popBackStack() })
    }
}
