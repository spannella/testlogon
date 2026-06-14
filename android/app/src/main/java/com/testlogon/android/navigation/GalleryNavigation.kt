package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.gallery.GalleryRoute

/** AND-201 — the published video gallery browse grid. */
data object GalleryDest {
    const val ROUTE = "gallery"
}

/**
 * AND-201 — registers the gallery grid; tapping a card opens the existing shared video detail
 * destination (AND-190), so there is no duplicate detail screen.
 */
fun NavGraphBuilder.galleryDestination(navController: NavHostController) {
    composable(GalleryDest.ROUTE) {
        GalleryRoute(
            onItemClick = { videoId ->
                navController.navigate(VideoDetailDest.build(videoId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
