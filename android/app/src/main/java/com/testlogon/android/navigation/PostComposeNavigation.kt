package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.feed.compose.ComposePostRoute

/**
 * Newsfeed post-compose screen (create a post). Reached from the feed compose FAB.
 *
 * #4 (B-GROUPUNIFY) — the SAME composer also creates GROUP posts: pass [ARG_GROUP_ID] (optional) to
 * pre-select + lock the audience to a group (used when composing from a group feed). When absent, the
 * audience defaults to the personal feed and the user may pick any of their groups in-composer.
 */
data object ComposePostDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE_BASE = "compose_post"
    const val ROUTE = "$ROUTE_BASE?$ARG_GROUP_ID={$ARG_GROUP_ID}"

    /** Open the composer with no fixed audience (personal feed default). */
    fun build(): String = ROUTE_BASE

    /** Open the composer locked to a specific group's audience. */
    fun buildForGroup(groupId: String): String = "$ROUTE_BASE?$ARG_GROUP_ID=${Uri.encode(groupId)}"
}

fun NavGraphBuilder.composePostDestination(navController: NavHostController) {
    composable(
        route = ComposePostDest.ROUTE,
        arguments = listOf(
            navArgument(ComposePostDest.ARG_GROUP_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        ComposePostRoute(onBack = { navController.popBackStack() })
    }
}
