package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.feed.scheduled.ScheduledPostsRoute

/**
 * PAR-13 — the scheduled-posts management destination (`scheduled_posts`). Arg-less: the screen loads the
 * caller's pending scheduled posts from GET /posts/scheduled and cancels via POST /posts/{id}/cancel.
 * Reached from the Feed top-bar. Entering while unauthenticated is handled by the authenticated graph.
 */
data object ScheduledPostsDest {
    const val ROUTE = "scheduled_posts"
}

/** PAR-13 — navigation seam used by the Feed toolbar entry. */
fun NavController.navigateToScheduledPosts() {
    navigate(ScheduledPostsDest.ROUTE) { launchSingleTop = true }
}

/** PAR-13 — registers the `scheduled_posts` destination. */
fun NavGraphBuilder.scheduledPostsDestination(navController: NavHostController) {
    composable(route = ScheduledPostsDest.ROUTE) {
        ScheduledPostsRoute(onBack = { navController.popBackStack() })
    }
}
