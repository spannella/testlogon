package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adminvideo.VideoReviewRoute

/**
 * B5 - the admin video-review queue, registered in the AUTHENTICATED graph. Role-gated (backend 403 ->
 * Forbidden). Mirrors the web /admin/video-review page (approve/reject).
 */
data object VideoReviewDest {
    const val ROUTE = "admin/video-review"
}

fun NavGraphBuilder.videoReviewDestination(navController: NavHostController) {
    composable(VideoReviewDest.ROUTE) {
        VideoReviewRoute(onBack = { navController.popBackStack() })
    }
}
