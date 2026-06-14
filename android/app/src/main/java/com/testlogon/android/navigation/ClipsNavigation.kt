package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.clips.ClipsRoute
import com.testlogon.android.feature.clips.PublicClipRoute
import com.testlogon.android.feature.clips.PublicClipViewModel

/** AND-196 — the authenticated clips vertical pager (gallery feed). */
data object ClipsFeedDest {
    const val ROUTE = "clips"
}

/**
 * AND-196 — public single-clip viewer route `c/{clipId}`. Mirrors the web share URL
 * `https://testlogon.app/c/{clipId}`; works for UNAUTHENTICATED users (public clips). Registered in
 * both top-level graphs so a shared link resolves whether or not the viewer is signed in.
 */
data object PublicClipDest {
    const val ROUTE = "c/{${PublicClipViewModel.ARG_CLIP_ID}}"
    const val DEEP_LINK_PATH = "/c"

    fun build(clipId: String): String = "c/${Uri.encode(clipId)}"
}

/** AND-196 — registers the authenticated clips pager; its author tap opens the public profile. */
fun NavGraphBuilder.clipsFeedDestination(navController: NavHostController) {
    composable(ClipsFeedDest.ROUTE) {
        ClipsRoute(
            onBack = { navController.popBackStack() },
            onOpenProfile = { id ->
                navController.navigate(PublicProfileDest.build(id)) { launchSingleTop = true }
            },
        )
    }
}

/**
 * AND-196 — registers the public clip destination with its `c/{clipId}` route + App Link / dev-host /
 * custom-scheme deep links. On a cold deep-link start the back stack may be empty; Back falls back to
 * the graph start. Registered in BOTH graphs (the public read is auth-optional).
 */
fun NavGraphBuilder.publicClipDestination(navController: NavHostController) {
    composable(
        route = PublicClipDest.ROUTE,
        arguments = listOf(
            navArgument(PublicClipViewModel.ARG_CLIP_ID) { type = NavType.StringType },
        ),
        deepLinks = publicClipDeepLinks(),
    ) {
        PublicClipRoute(
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
            onOpenFeed = {
                navController.navigate(ClipsFeedDest.ROUTE) { launchSingleTop = true }
            },
            // AND-394 — anonymous→app bridge (FR-6/AC-7). The public destination is registered in BOTH
            // graphs, so we route to the current graph's start: the login screen when unauthenticated, or
            // the authenticated home when a session exists. The destination is best-effort (the screen
            // already decides the CTA label by session); a missing route falls back to the graph start.
            onOpenAuth = {
                val start = navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED
                navController.navigate(start) { launchSingleTop = true }
            },
        )
    }
}

/**
 * Deep links for `/c/{clipId}`: a verified HTTPS App Link on the production host, a plaintext HTTP
 * tap-through on the dev host, and a custom-scheme fallback for share flows.
 */
private fun publicClipDeepLinks(): List<NavDeepLink> {
    val path = PublicClipDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{clipId}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{clipId}" },
        navDeepLink { uriPattern = "testlogon://c/{clipId}" },
    )
}
