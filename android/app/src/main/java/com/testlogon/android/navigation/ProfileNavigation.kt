package com.testlogon.android.navigation

import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.profile.publicprofile.PublicProfileRoute

/**
 * AND-073 — registers the public-profile destination ([PublicProfileDest]) with its `/u/{identifier}`
 * App Link + custom-scheme deep links. Registered in both top-level graphs (the public read is
 * auth-optional) so a shared link resolves whether or not the viewer is signed in.
 *
 * `identifier` is URL-decoded once by Navigation and passed verbatim to the screen.
 */
fun NavGraphBuilder.publicProfileDestination(
    navController: NavHostController,
    // AND-238: only the authenticated graph wires the fan-club entry (the route is auth-only).
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
) {
    composable(
        route = PublicProfileDest.ROUTE,
        arguments = listOf(
            navArgument(PublicProfileDest.ARG_IDENTIFIER) { type = NavType.StringType },
        ),
        deepLinks = publicProfileDeepLinks(),
    ) {
        PublicProfileRoute(
            onOpenFanClub = onOpenFanClub,
            onBack = {
                // From a deep-link cold start the back stack may be empty; fall back to the start dest.
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}

/**
 * Deep links for `/u/{identifier}`: a verified HTTPS App Link on the production host, a plaintext HTTP
 * tap-through on the dev host, and a custom-scheme fallback for share flows.
 */
private fun publicProfileDeepLinks(): List<NavDeepLink> {
    val path = PublicProfileDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{identifier}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{identifier}" },
        navDeepLink { uriPattern = "testlogon://u/{identifier}" },
    )
}
