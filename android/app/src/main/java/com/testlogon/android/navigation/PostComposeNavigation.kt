package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.feed.compose.ComposePostRoute

/** Newsfeed post-compose screen (create a post). Reached from the feed compose FAB. */
data object ComposePostDest {
    const val ROUTE = "compose_post"
}

fun NavGraphBuilder.composePostDestination(navController: NavHostController) {
    composable(ComposePostDest.ROUTE) {
        ComposePostRoute(onBack = { navController.popBackStack() })
    }
}
