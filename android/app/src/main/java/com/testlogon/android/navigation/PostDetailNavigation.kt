package com.testlogon.android.navigation

import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.ads.cta.CtaDestination
import com.testlogon.android.feature.ads.cta.navigateCta
import com.testlogon.android.feature.feed.PostDetailRoute

/**
 * AND-100 — registers the read-only post-detail destination ([PostDetailDest]) with its
 * `post/{postId}` route + deep links: a verified HTTPS App Link on the production host, a plaintext
 * HTTP tap-through on the dev host, and a custom-scheme fallback for share flows.
 *
 * On a cold deep-link start the back stack may be empty; Back falls back to the graph start so the
 * system Back returns into the app rather than exiting.
 */
fun NavGraphBuilder.postDetailDestination(navController: NavHostController) {
    composable(
        route = PostDetailDest.ROUTE,
        arguments = listOf(
            navArgument(PostDetailDest.ARG_POST_ID) { type = NavType.StringType },
        ),
        deepLinks = postDetailDeepLinks(),
    ) {
        PostDetailRoute(
            // TIPX-B3 (F3) - empty-wallet tipper adds a card in-flow, then returns to the tip sheet.
            onAddCard = { navController.navigate(AddCardDest.ROUTE) { launchSingleTop = true } },
            // SUB-E3-2 - a subscriber-only post lock card opens this creator subscribe flow.
            onSubscribeClick = { creatorId ->
                if (creatorId.isNotBlank()) {
                    navController.navigateCta(CtaDestination.Subscriptions(creatorId))
                }
            },
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.AUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}

private fun postDetailDeepLinks(): List<NavDeepLink> {
    val path = PostDetailDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{postId}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{postId}" },
        navDeepLink { uriPattern = "testlogon://post/{postId}" },
    )
}
