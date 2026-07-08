package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.vod.adsupported.AdSupportedPlayerRoute
import com.testlogon.android.feature.vod.adsupported.AdSupportedPlayerViewModel

/**
 * ADV-202 - video pre-roll (AVOD) player route `video-avod/{videoId}`. Plays the live pre-roll ad
 * (backend ADV-201 serve_ad surface=preroll) before the gated main video, then charges the advertiser
 * + credits the poster on completion (backend ADV-203). Reached from the VOD catalog and directly via
 * the `testlogon://avod/{videoId}` custom-scheme deep link (see AndroidManifest) for verification.
 */
data object AdSupportedPlayerDest {
    const val ROUTE = "video-avod/{${AdSupportedPlayerViewModel.ARG_VIDEO_ID}}"

    fun build(videoId: String): String = "video-avod/${Uri.encode(videoId)}"
}

/** Registers the pre-roll AVOD player destination with its route + custom-scheme deep link. */
fun NavGraphBuilder.adSupportedPlayerDestination(navController: NavHostController) {
    composable(
        route = AdSupportedPlayerDest.ROUTE,
        arguments = listOf(
            navArgument(AdSupportedPlayerViewModel.ARG_VIDEO_ID) { type = NavType.StringType },
        ),
        deepLinks = adSupportedPlayerDeepLinks(),
    ) {
        AdSupportedPlayerRoute(
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

private fun adSupportedPlayerDeepLinks(): List<NavDeepLink> = listOf(
    navDeepLink { uriPattern = "testlogon://avod/{${AdSupportedPlayerViewModel.ARG_VIDEO_ID}}" },
)
