package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.videos.VideosRoute
import com.testlogon.android.feature.videos.detail.VideoDetailRoute
import com.testlogon.android.feature.videos.detail.VideoDetailViewModel
import com.testlogon.android.feature.vod.VodCatalogRoute

/** AND-189 — the caller's videos library grid. */
data object VideosLibraryDest {
    const val ROUTE = "videos"
}

/** AND-191 — the public VOD catalog (browse on-demand titles). */
data object VodCatalogDest {
    const val ROUTE = "vod/catalog"
}

/**
 * AND-190 — video detail + player route `video/{videoId}`. Shared by the videos library (AND-189), the
 * VOD catalog (AND-191), and the discover "for you" recommendations (AND-184, previously a no-op). A
 * deep link mirrors the web `/gallery/{video_id}` detail page.
 */
data object VideoDetailDest {
    const val ROUTE = "video/{${VideoDetailViewModel.ARG_VIDEO_ID}}"
    const val DEEP_LINK_PATH = "/gallery"

    fun build(videoId: String): String = "video/${Uri.encode(videoId)}"
}

/** AND-189 — registers the videos library; its tiles open [VideoDetailDest]. */
fun NavGraphBuilder.videosLibraryDestination(navController: NavHostController) {
    composable(VideosLibraryDest.ROUTE) {
        VideosRoute(
            onOpenVideo = { id ->
                navController.navigate(VideoDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/** AND-191 — registers the VOD catalog; its tiles open the shared [VideoDetailDest]. */
fun NavGraphBuilder.vodCatalogDestination(navController: NavHostController) {
    composable(VodCatalogDest.ROUTE) {
        VodCatalogRoute(
            onVodClick = { id ->
                navController.navigate(VideoDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-190 — registers the video detail destination with its `video/{videoId}` route + deep links.
 * On a cold deep-link start the back stack may be empty; Back falls back to the graph start.
 */
fun NavGraphBuilder.videoDetailDestination(navController: NavHostController) {
    composable(
        route = VideoDetailDest.ROUTE,
        arguments = listOf(
            navArgument(VideoDetailViewModel.ARG_VIDEO_ID) { type = NavType.StringType },
        ),
        deepLinks = videoDetailDeepLinks(),
    ) {
        VideoDetailRoute(
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.AUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
            onOpenVideo = { id ->
                navController.navigate(VideoDetailDest.build(id)) { launchSingleTop = true }
            },
        )
    }
}

private fun videoDetailDeepLinks(): List<NavDeepLink> {
    val path = VideoDetailDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{videoId}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{videoId}" },
        navDeepLink { uriPattern = "testlogon://gallery/{videoId}" },
    )
}
